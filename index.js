/*
 * Multi-Protocol Proxy Server (SOCKS4, SOCKS5, HTTP) with User Management and Bandwidth Throttling
 *
 * Description:
 * This Node.js script creates a proxy server that handles SOCKS4, SOCKS5, and HTTP requests.
 * It features a persistent user management system using SQLite, per-user bandwidth throttling,
 * and subscription management with an admin panel.
 *
 * Features:
 * - Supports SOCKSv4, SOCKSv5, and HTTP/HTTPS (CONNECT) protocols.
 * - Protocol auto-detection on a single port.
 * - Per-user authentication, bandwidth throttling, and subscription expiry.
 * - Persistent user database using SQLite with automated schema migration.
 * - Web admin panel for user management and viewing earnings statistics.
 *
 * How to Run:
 * 1. Save this code as `proxy.js`.
 * 2. Install the required dependency: `npm install sqlite3`
 * 3. Configure the settings below.
 * 4. Run from your terminal: `node proxy.js`
 */

const net = require('net');
const dns = require('dns');
const { Buffer } = require('buffer');
const { Duplex } = require('stream');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const querystring = require('querystring');
const { URL } = require('url');


// --- CONFIGURATION ---

const PROXY_PORT = 8080;
const ADMIN_PORT = 8081; // Port for the web admin panel
const DB_FILE = './proxy_users.db';
const ALLOW_UNAUTHENTICATED = false; // If true, allows connections without a valid user.

// --- Admin Panel Credentials ---
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'changeme'; // IMPORTANT: Change this password!

// This list is used to populate the DB only on the first run.
const initialUsers = {
    'demo': {
        password: 'password123',
        throttle: 250 * 1024, // 250 KB/s (~1.95 Mbps)
        bill_amount: 5,
        valid_until: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] // 30 days from now
    },
    'poweruser': {
        password: 'strongpassword',
        throttle: 2 * 1024 * 1024, // 2 MB/s (16 Mbps)
        bill_amount: 20,
        valid_until: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
    },
    'unlimited': {
        password: 'freeuser',
        throttle: -1, // -1 means unlimited speed
        bill_amount: 0,
        valid_until: '2099-12-31'
    }
};

// In-memory cache for users, loaded from the database on startup.
let users = {};

// --- DATABASE MANAGEMENT ---
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1);
    }
    log('Successfully connected to the SQLite database.');
});

function initializeDatabase() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Create table if it doesn't exist
            db.run(`CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                throttle INTEGER NOT NULL,
                valid_until TEXT,
                bill_amount REAL DEFAULT 0,
                created_at TEXT
            )`, (err) => {
                if (err) return reject(err);
                log('Users table checked/created.');

                // Add new columns for backward compatibility (migration)
                const columns = ['valid_until TEXT', 'bill_amount REAL DEFAULT 0', 'created_at TEXT'];
                columns.forEach(column => {
                    db.run(`ALTER TABLE users ADD COLUMN ${column}`, () => { /* Ignore errors if column exists */ });
                });

                db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
                    if (err) return reject(err);
                    if (row.count === 0) {
                        log('Users table is empty. Populating with initial users...');
                        const stmt = db.prepare('INSERT INTO users (username, password, throttle, bill_amount, valid_until, created_at) VALUES (?, ?, ?, ?, ?, ?)');
                        for (const username in initialUsers) {
                            const user = initialUsers[username];
                            stmt.run(username, user.password, user.throttle, user.bill_amount, user.valid_until, new Date().toISOString());
                        }
                        stmt.finalize((err) => {
                            if (err) return reject(err);
                            log('Initial users have been added.');
                            loadUsersFromDb().then(resolve).catch(reject);
                        });
                    } else {
                        loadUsersFromDb().then(resolve).catch(reject);
                    }
                });
            });
        });
    });
}

function loadUsersFromDb() {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM users', (err, rows) => {
            if (err) return reject(err);
            const newUsers = {};
            rows.forEach(row => {
                newUsers[row.username] = {
                    password: row.password,
                    throttle: row.throttle,
                    valid_until: row.valid_until,
                    bill_amount: row.bill_amount
                };
            });
            users = newUsers; // Atomically swap the cache
            log(`Reloaded ${Object.keys(users).length} users from the database.`);
            resolve();
        });
    });
}


// --- BANDWIDTH THROTTLING ---
class ThrottledStream extends Duplex {
    constructor(rate) { // rate in bytes per second
        super();
        this.rate = rate;
        this.buffer = [];
        this.isProcessing = false;
        this.startTime = Date.now();
        this.bytesProcessed = 0;
    }
    _write(chunk, encoding, callback) {
        this.buffer.push({ chunk, callback });
        if (!this.isProcessing) { this._processBuffer(); }
    }
    _read(size) { /* No-op */ }
    _processBuffer() {
        if (this.buffer.length === 0) { this.isProcessing = false; return; }
        this.isProcessing = true;
        const { chunk, callback } = this.buffer.shift();
        this.push(chunk);
        this.bytesProcessed += chunk.length;
        const elapsedTime = (Date.now() - this.startTime) / 1000;
        const expectedTime = (this.bytesProcessed / this.rate);
        const delay = Math.max(0, (expectedTime - elapsedTime) * 1000);
        callback();
        setTimeout(() => this._processBuffer(), delay);
    }
}


// --- USER MANAGEMENT ---
function findUser(username) {
    const user = users[username] || null;
    if (!user) return null;

    // Check for expiry
    if (user.valid_until) {
        // Add 1 day to make the expiry inclusive of the last day
        const expiryDate = new Date(user.valid_until);
        expiryDate.setDate(expiryDate.getDate() + 1);
        if (expiryDate < new Date()) {
            log(`Authentication check: User '${username}' has expired on ${user.valid_until}.`);
            return null;
        }
    }
    return user;
}

function authenticate(username, password) {
    const user = findUser(username);
    return user && user.password === password ? user : null;
}

// --- MAIN PROXY SERVER ---
const server = net.createServer((clientSocket) => {
    log(`Client connected from ${clientSocket.remoteAddress}:${clientSocket.remotePort}`);
    clientSocket.once('data', (initialData) => {
        const protocolByte = initialData[0];
        if (protocolByte === 0x05) { handleSocks5(clientSocket, initialData); }
        else if (protocolByte === 0x04) { handleSocks4(clientSocket, initialData); }
        else { handleHttp(clientSocket, initialData); }
    });
    clientSocket.on('error', (err) => { log(`Client socket error: ${err.message}`); clientSocket.destroy(); });
    clientSocket.on('close', () => { log(`Client disconnected`); });
});


// --- PROTOCOL HANDLERS ---
function handleSocks5(clientSocket, initialData) {
    log('SOCKS5 protocol detected');
    let user = null;
    let state = 'handshake';

    // Step 1: Client Greeting
    const nmethods = initialData[1];
    const methods = initialData.slice(2, 2 + nmethods);
    
    let authMethod = 0xFF; // No acceptable method by default
    // Prioritize User/Pass if client supports it
    if (methods.includes(0x02)) { authMethod = 0x02; } 
    // Fallback to No Auth only if it's allowed by config and supported by client
    else if (ALLOW_UNAUTHENTICATED && methods.includes(0x00)) { authMethod = 0x00; }
    
    if (authMethod === 0xFF) {
        log('SOCKS5: No acceptable authentication method. Closing connection.');
        clientSocket.end(Buffer.from([0x05, 0xFF]));
        return;
    }

    // Step 2: Server Choice
    clientSocket.write(Buffer.from([0x05, authMethod]));

    if (authMethod === 0x00) { state = 'request'; }
    else if (authMethod === 0x02) { state = 'authentication'; }

    clientSocket.on('data', socks5Handler);

    function socks5Handler(data) {
        // Step 3: Authentication
        if (state === 'authentication') {
            const usernameLen = data[1];
            const username = data.slice(2, 2 + usernameLen).toString('utf8');
            const passwordLen = data[2 + usernameLen];
            const password = data.slice(3 + usernameLen, 3 + usernameLen + passwordLen).toString('utf8');
            user = authenticate(username, password);
            if (user) {
                log(`SOCKS5: User '${username}' authenticated successfully.`);
                clientSocket.write(Buffer.from([0x01, 0x00])); // Auth success
                state = 'request';
            } else {
                log(`SOCKS5: User '${username}' authentication failed (invalid credentials or expired).`);
                clientSocket.end(Buffer.from([0x01, 0x01])); // Auth failure
            }
            return;
        }

        // Step 4: Client Request
        if (state === 'request') {
            const [ver, cmd, rsv, atyp] = data;
            if (ver !== 0x05 || cmd !== 0x01) { // We only support CONNECT command
                clientSocket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return;
            }
            
            let host, port, addrEndOffset;
            if (atyp === 0x01) { // IPv4
                host = data.slice(4, 8).join('.'); port = data.readUInt16BE(8); addrEndOffset = 10;
            } else if (atyp === 0x03) { // Domain name
                const hostLen = data[4]; host = data.slice(5, 5 + hostLen).toString('utf8'); port = data.readUInt16BE(5 + hostLen); addrEndOffset = 5 + hostLen + 2;
            } else if (atyp === 0x04) { // IPv6
                host = data.slice(4, 20).toString('hex').match(/.{1,4}/g).join(':'); port = data.readUInt16BE(20); addrEndOffset = 22;
            } else {
                clientSocket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return;
            }
            
            log(`SOCKS5: Connecting to ${host}:${port}`);
            clientSocket.removeListener('data', socks5Handler);
            
            createRemoteConnection(clientSocket, user, host, port, (remoteSocket) => {
                // Step 5: Server Reply
                const reply = Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                clientSocket.write(reply);
                pipeData(clientSocket, remoteSocket, user, `SOCKS5`);
                const remainingData = data.slice(addrEndOffset);
                if (remainingData.length > 0) { remoteSocket.write(remainingData); }
            }, (err) => {
                log(`SOCKS5: Connection to ${host}:${port} failed: ${err.message}`);
                const reply = Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                clientSocket.end(reply);
            });
        }
    }
}

function handleSocks4(clientSocket, initialData) {
    log('SOCKS4 protocol detected');
    const cmd = initialData[1];
    if (cmd !== 0x01) { clientSocket.end(Buffer.from([0x00, 0x5B, 0, 0, 0, 0, 0, 0])); return; }
    
    const port = initialData.readUInt16BE(2);
    let ip = initialData.slice(4, 8).join('.');
    const nullByteIndex = initialData.indexOf(0x00, 8);
    const userId = initialData.slice(8, nullByteIndex).toString('utf8');
    
    const user = findUser(userId);
    log(`SOCKS4: Attempting connection for user '${userId}'`);
    if (!user) {
        log(`SOCKS4: User '${userId}' not found, expired, or unconfigured.`);
        if (!ALLOW_UNAUTHENTICATED) {
            log('SOCKS4: Unauthenticated access denied.');
            clientSocket.end(Buffer.from([0x00, 0x5B, 0, 0, 0, 0, 0, 0])); // Request rejected
            return;
        }
    }
    
    let host = ip;
    // SOCKS4a extension: if IP is 0.0.0.x, read domain name
    if (initialData[4] === 0 && initialData[5] === 0 && initialData[6] === 0 && initialData[7] !== 0) {
        const domainNullByteIndex = initialData.indexOf(0x00, nullByteIndex + 1);
        host = initialData.slice(nullByteIndex + 1, domainNullByteIndex).toString('utf8');
    }
    
    log(`SOCKS4: Connecting to ${host}:${port}`);
    createRemoteConnection(clientSocket, user, host, port, (remoteSocket) => {
        clientSocket.write(Buffer.from([0x00, 0x5A, 0, 0, 0, 0, 0, 0])); // Success
        pipeData(clientSocket, remoteSocket, user, `SOCKS4`);
    }, (err) => {
        log(`SOCKS4: Connection to ${host}:${port} failed: ${err.message}`);
        clientSocket.end(Buffer.from([0x00, 0x5B, 0, 0, 0, 0, 0, 0])); // Failure
    });
}

function handleHttp(clientSocket, initialData) {
    log('HTTP protocol detected');
    const requestStr = initialData.toString('utf8');
    const [requestLine] = requestStr.split('\r\n');
    const [method, url, version] = requestLine.split(' ');

    if (!method || !url || !version) { 
        clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); 
        return; 
    }
    
    let user = null;
    const authHeaderMatch = requestStr.match(/Proxy-Authorization: Basic (.+)\r\n/i);
    if (authHeaderMatch) {
        const credentials = Buffer.from(authHeaderMatch[1], 'base64').toString('utf8');
        const [username, password] = credentials.split(':');
        user = authenticate(username, password);
        if (!user) {
            log(`HTTP: User '${username}' authentication failed (invalid credentials or expired).`);
            clientSocket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
            return;
        }
        log(`HTTP: User '${username}' authenticated successfully.`);
    } else if (!ALLOW_UNAUTHENTICATED) {
        log('HTTP: Authentication required, but no credentials provided.');
        clientSocket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
        return;
    }
    
    if (method.toUpperCase() === 'CONNECT') {
        const [host, portStr] = url.split(':');
        const port = parseInt(portStr, 10) || 443;
        log(`HTTPS CONNECT: Connecting to ${host}:${port}`);
        createRemoteConnection(clientSocket, user, host, port, (remoteSocket) => {
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            pipeData(clientSocket, remoteSocket, user, 'HTTPS CONNECT');
        }, (err) => {
            clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
        });
    } else {
        try {
            const parsedUrl = new URL(url);
            const host = parsedUrl.hostname; 
            const port = parsedUrl.port || 80;
            log(`HTTP ${method}: Connecting to ${host}:${port}`);
            createRemoteConnection(clientSocket, user, host, port, (remoteSocket) => {
                remoteSocket.write(initialData);
                pipeData(clientSocket, remoteSocket, user, `HTTP ${method}`);
            }, (err) => {
                clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
            });
        } catch (error) { 
            clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); 
        }
    }
}

// --- UTILITY FUNCTIONS ---
function createRemoteConnection(clientSocket, user, host, port, successCallback, errorCallback) {
    dns.lookup(host, (err, address) => {
        if (err) { return errorCallback(err); }
        const remoteSocket = net.createConnection({ host: address, port: port }, () => { 
            successCallback(remoteSocket); 
        });
        remoteSocket.on('error', (err) => {
            log(`Remote socket error connecting to ${host}:${port} - ${err.message}`);
            errorCallback(err);
            if (!clientSocket.destroyed) clientSocket.destroy();
        });
    });
}

function pipeData(clientSocket, remoteSocket, user, connectionType) {
    const userLabel = user ? user.username : 'unauthenticated';
    const throttleRate = user ? user.throttle : -1;
    log(`Piping data for ${connectionType} connection. User: ${userLabel}. Throttle: ${throttleRate === -1 ? 'Unlimited' : `${((throttleRate * 8) / (1024 * 1024)).toFixed(2)} Mbps`}`);
    
    if (throttleRate > 0) {
        const clientToRemoteThrottler = new ThrottledStream(throttleRate);
        const remoteToClientThrottler = new ThrottledStream(throttleRate);
        clientSocket.pipe(clientToRemoteThrottler).pipe(remoteSocket);
        remoteSocket.pipe(remoteToClientThrottler).pipe(clientSocket);
    } else {
        clientSocket.pipe(remoteSocket);
        remoteSocket.pipe(clientSocket);
    }
    
    clientSocket.on('close', () => remoteSocket.destroy());
    remoteSocket.on('close', () => clientSocket.destroy());
    clientSocket.on('error', (err) => log(`Client pipe error for ${userLabel}: ${err.message}`));
    remoteSocket.on('error', (err) => log(`Remote pipe error for ${userLabel}: ${err.message}`));
}
function log(message) { console.log(`[${new Date().toISOString()}] ${message}`); }


// --- ADMIN PANEL SERVER ---
const adminServer = http.createServer(async (req, res) => {
    try {
        const cookies = querystring.parse(req.headers.cookie, '; ');
        const sessionId = cookies.sessionId || '';
        const isAuthenticated = sessionStore[sessionId];
        const url = new URL(req.url, `http://${req.headers.host}`);
        const pathname = url.pathname;

        if (pathname === '/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', () => {
                const { username, password } = querystring.parse(body);
                if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
                    const newSessionId = require('crypto').randomBytes(16).toString('hex');
                    sessionStore[newSessionId] = true;
                    res.writeHead(302, { 'Set-Cookie': `sessionId=${newSessionId}; HttpOnly; Path=/`, 'Location': '/' });
                    res.end();
                } else {
                    res.writeHead(302, { 'Location': '/?error=1' });
                    res.end();
                }
            }); 
            return;
        }

        if (pathname === '/logout') {
            delete sessionStore[sessionId];
            res.writeHead(302, { 'Set-Cookie': `sessionId=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`, 'Location': '/' });
            res.end();
            return;
        }

        if (!isAuthenticated) { 
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(getLoginPage(url.search.includes('error=1'))); 
            return; 
        }

        // --- Authenticated Routes ---
        if (pathname === '/') {
            const filter = url.searchParams.get('filter') || 'all';

            let whereClause = '';
            if (filter === 'active') {
                whereClause = `WHERE valid_until >= date('now')`;
            } else if (filter === 'inactive') {
                whereClause = `WHERE valid_until < date('now')`;
            }
            
            const userList = await dbAll(`SELECT * FROM users ${whereClause}`, []);
            const today = new Date().toISOString().slice(0, 10);
            const month = new Date().toISOString().slice(0, 7);

            const earningsToday = await dbGet("SELECT SUM(bill_amount) as total FROM users WHERE date(created_at) = ?", [today]);
            const earningsMonth = await dbGet("SELECT SUM(bill_amount) as total FROM users WHERE strftime('%Y-%m', created_at) = ?", [month]);
            const earningsTotal = await dbGet("SELECT SUM(bill_amount) as total FROM users", []);

            const stats = {
                today: earningsToday.total || 0,
                month: earningsMonth.total || 0,
                total: earningsTotal.total || 0,
            };
            
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(getDashboardPage(userList, stats, { filter }));

        } else if (pathname === '/add-user' && req.method === 'POST') {
            let body = ''; 
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                const { username, password, throttle, bill_amount, valid_until } = querystring.parse(body);
                const query = 'INSERT INTO users (username, password, throttle, bill_amount, valid_until, created_at) VALUES (?, ?, ?, ?, ?, ?)';
                const params = [username, password, parseInt(throttle, 10), parseFloat(bill_amount), valid_until, new Date().toISOString()];
                db.run(query, params, async function(err) {
                    await loadUsersFromDb(); 
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                });
            });
        } else if (pathname === '/edit-user' && req.method === 'POST') {
            let body = ''; 
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                const { username, password, throttle, bill_amount, valid_until } = querystring.parse(body);
                const query = password ? 'UPDATE users SET password = ?, throttle = ?, bill_amount = ?, valid_until = ? WHERE username = ?' : 'UPDATE users SET throttle = ?, bill_amount = ?, valid_until = ? WHERE username = ?';
                const params = password ? [password, parseInt(throttle, 10), parseFloat(bill_amount), valid_until, username] : [parseInt(throttle, 10), parseFloat(bill_amount), valid_until, username];
                db.run(query, params, async function(err) {
                    await loadUsersFromDb(); 
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                });
            });
        } else if (pathname === '/delete-user' && req.method === 'POST') {
            let body = ''; 
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                const { username } = querystring.parse(body);
                db.run('DELETE FROM users WHERE username = ?', username, async function(err) {
                    await loadUsersFromDb(); 
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                });
            });
        } else if (pathname === '/delete-users' && req.method === 'POST') {
             let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                const { usernames } = querystring.parse(body);
                if (!usernames || (Array.isArray(usernames) && usernames.length === 0)) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'No users selected' }));
                    return;
                }
                const usersToDelete = Array.isArray(usernames) ? usernames : [usernames];
                const placeholders = usersToDelete.map(() => '?').join(',');
                
                db.run(`DELETE FROM users WHERE username IN (${placeholders})`, usersToDelete, async function(err) {
                    if (err) {
                        log(`Error deleting users: ${err.message}`);
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ message: 'Failed to delete users' }));
                        return;
                    }
                    await loadUsersFromDb();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Users deleted successfully' }));
                });
            });
        } else { 
            res.writeHead(404);
            res.end('Not Found'); 
        }
    } catch (e) { 
        log(`Admin panel error: ${e.message}`); 
        res.writeHead(500);
        res.end('Server Error');
    }
});

const sessionStore = {}; // Simple in-memory session store
// Promisify db.get and db.all for async/await
const dbGet = (sql, params) => new Promise((resolve, reject) => { db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)); });
const dbAll = (sql, params) => new Promise((resolve, reject) => { db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)); });

function getLoginPage(error = false) { /* Unchanged from previous version */ 
    return `
    <!DOCTYPE html>
    <html lang="en" class="bg-gray-900 text-white">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="flex items-center justify-center min-h-screen">
        <div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
            <h2 class="text-3xl font-bold text-center text-white">Proxy Admin Login</h2>
            ${error ? `<div class="p-4 text-sm text-red-400 bg-red-900/50 rounded-lg" role="alert">Invalid username or password.</div>` : ''}
            <form action="/login" method="POST" class="space-y-6">
                <div>
                    <label for="username" class="block mb-2 text-sm font-medium text-gray-300">Username</label>
                    <input type="text" name="username" id="username" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" required>
                </div>
                <div>
                    <label for="password" class="block mb-2 text-sm font-medium text-gray-300">Password</label>
                    <input type="password" name="password" id="password" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" required>
                </div>
                <button type="submit" class="w-full px-5 py-2.5 text-base font-medium text-center text-white bg-blue-600 rounded-lg hover:bg-blue-700 focus:ring-4 focus:ring-blue-800">Login</button>
            </form>
        </div>
    </body>
    </html>
    `;
}

function getDashboardPage(userList, stats, pageOptions) {
    const { filter } = pageOptions;
    
    const filterButton = (name, value) => {
        const isActive = filter === value;
        const classes = isActive 
            ? 'px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg' 
            : 'px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 rounded-lg hover:bg-gray-600';
        return `<a href="/?filter=${value}" class="${classes}">${name}</a>`;
    };

    return `
    <!DOCTYPE html>
    <html lang="en" class="bg-gray-900 text-white">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            .sortable:hover { cursor: pointer; background-color: #374151; }
            .sort-icon { display: inline-block; width: 1em; height: 1em; margin-left: 0.5em; opacity: 0.5; }
            .sort-asc .sort-icon { content: '▲'; opacity: 1; }
            .sort-desc .sort-icon { content: '▼'; opacity: 1; }
        </style>
    </head>
    <body class="p-4 sm:p-6 md:p-8">
        <div class="max-w-7xl mx-auto">
            <header class="flex flex-wrap items-center justify-between gap-4 mb-8">
                <h1 class="text-3xl font-bold">Proxy User Management</h1>
                <div>
                    <button onclick="openAddModal()" class="px-5 py-2.5 text-base font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 focus:ring-4 focus:ring-blue-800 mr-4">Add User</button>
                    <a href="/logout" class="px-5 py-2.5 text-base font-medium text-white bg-gray-600 rounded-lg hover:bg-gray-700 focus:ring-4 focus:ring-gray-800">Logout</a>
                </div>
            </header>

            <!-- Stats -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="p-6 bg-gray-800 rounded-lg"><p class="text-sm text-gray-400">Earnings Today</p><p class="text-3xl font-bold">$${stats.today.toFixed(2)}</p></div>
                <div class="p-6 bg-gray-800 rounded-lg"><p class="text-sm text-gray-400">Earnings This Month</p><p class="text-3xl font-bold">$${stats.month.toFixed(2)}</p></div>
                <div class="p-6 bg-gray-800 rounded-lg"><p class="text-sm text-gray-400">Total Earnings</p><p class="text-3xl font-bold">$${stats.total.toFixed(2)}</p></div>
            </div>

            <div class="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div class="flex items-center gap-2">
                    ${filterButton('All Users', 'all')}
                    ${filterButton('Active', 'active')}
                    ${filterButton('Inactive', 'inactive')}
                </div>
                 <div class="flex items-center gap-4">
                    <input type="text" id="searchInput" placeholder="Search users..." class="px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                    <button id="bulkDeleteBtn" class="px-5 py-2.5 text-base font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 focus:ring-4 focus:ring-red-800 disabled:opacity-50 disabled:cursor-not-allowed" disabled>Delete Selected</button>
                </div>
            </div>
            
            <div class="relative overflow-x-auto shadow-md sm:rounded-lg">
                <table class="w-full text-sm text-left text-gray-400">
                    <thead class="text-xs uppercase bg-gray-700 text-gray-400">
                        <tr>
                            <th scope="col" class="px-6 py-3"><input type="checkbox" id="selectAllCheckbox"></th>
                            <th scope="col" class="px-6 py-3 sortable" data-sort="username">Username <span class="sort-icon"></span></th>
                            <th scope="col" class="px-6 py-3 sortable" data-sort="status">Status <span class="sort-icon"></span></th>
                            <th scope="col" class="px-6 py-3 sortable" data-sort="throttle">Bandwidth <span class="sort-icon"></span></th>
                            <th scope="col" class="px-6 py-3 sortable" data-sort="bill_amount">Bill <span class="sort-icon"></span></th>
                            <th scope="col" class="px-6 py-3 sortable" data-sort="valid_until">Valid Until <span class="sort-icon"></span></th>
                            <th scope="col" class="px-6 py-3">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="userTableBody"></tbody>
                </table>
            </div>
            <div id="pagination-controls" class="flex flex-wrap items-center justify-between mt-6 gap-4"></div>
        </div>

        <!-- Modals and Forms -->
        <div id="userModal" class="fixed inset-0 z-50 items-center justify-center hidden bg-black bg-opacity-75" onclick="closeModal(event)"><div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg" onclick="event.stopPropagation()"><h3 id="modalTitle" class="text-2xl font-bold">Add New User</h3><form id="userForm" action="/add-user" method="POST" class="space-y-4"><input type="hidden" name="username" id="editUsername"><div><label for="username" class="block mb-2 text-sm font-medium">Username</label><input type="text" name="username" id="username" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg" required></div><div><label for="password" class="block mb-2 text-sm font-medium">Password <span id="passwordHint" class="text-xs text-gray-400"></span></label><input type="password" name="password" id="password" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg"></div><div class="grid grid-cols-2 gap-4"><div><label for="throttle" class="block mb-2 text-sm font-medium">Throttle (Mbps, -1=inf)</label><input type="number" step="0.01" name="throttle" id="throttle" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg" value="-1" required></div><div><label for="bill_amount" class="block mb-2 text-sm font-medium">Bill Amount ($)</label><input type="number" step="0.01" name="bill_amount" id="bill_amount" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg" value="0" required></div></div><div><label for="valid_until" class="block mb-2 text-sm font-medium">Valid Until</label><input type="date" name="valid_until" id="valid_until" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg" required><div class="flex gap-2 mt-2"><button type="button" onclick="addDays(7)" class="px-3 py-1 text-xs bg-gray-600 hover:bg-gray-500 rounded-md">7 Days</button><button type="button" onclick="addDays(15)" class="px-3 py-1 text-xs bg-gray-600 hover:bg-gray-500 rounded-md">15 Days</button><button type="button" onclick="addDays(30)" class="px-3 py-1 text-xs bg-gray-600 hover:bg-gray-500 rounded-md">30 Days</button></div></div><div class="flex justify-end gap-4 pt-4"><button type="button" onclick="closeModal()" class="px-5 py-2.5 text-base font-medium text-gray-300 bg-gray-700 rounded-lg hover:bg-gray-600">Cancel</button><button type="submit" class="px-5 py-2.5 text-base font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700">Save User</button></div></form></div></div>
        <div id="confirmModal" class="fixed inset-0 z-50 items-center justify-center hidden bg-black bg-opacity-75"><div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg"><h3 id="confirmTitle" class="text-xl font-bold">Confirm Action</h3><p id="confirmMessage">Are you sure?</p><div class="flex justify-end gap-4 pt-4"><button id="confirmCancelBtn" class="px-5 py-2.5 text-base font-medium text-gray-300 bg-gray-700 rounded-lg hover:bg-gray-600">Cancel</button><button id="confirmOkBtn" class="px-5 py-2.5 text-base font-medium text-white bg-red-600 rounded-lg hover:bg-red-700">Confirm</button></div></div></div>
        <div id="alertModal" class="fixed inset-0 z-50 items-center justify-center hidden bg-black bg-opacity-75"><div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg"><h3 id="alertTitle" class="text-xl font-bold text-yellow-400">Alert</h3><p id="alertMessage"></p><div class="flex justify-end gap-4 pt-4"><button id="alertOkBtn" class="px-5 py-2.5 text-base font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700">OK</button></div></div></div>
        <form id="deleteForm" action="/delete-user" method="POST" class="hidden"><input type="hidden" name="username" id="deleteUsername"></form>

        <script>
            // --- DATA and STATE ---
            const allUsers = ${JSON.stringify(userList)};
            let state = {
                users: allUsers,
                currentPage: 1,
                itemsPerPage: 10,
                sortColumn: 'username',
                sortDirection: 'asc',
                searchQuery: ''
            };

            document.addEventListener('DOMContentLoaded', () => {
                renderTable();

                document.getElementById('searchInput').addEventListener('input', (e) => {
                    state.searchQuery = e.target.value.toLowerCase();
                    state.currentPage = 1;
                    renderTable();
                });

                document.querySelectorAll('.sortable').forEach(header => {
                    header.addEventListener('click', () => {
                        const column = header.dataset.sort;
                        if (state.sortColumn === column) {
                            state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
                        } else {
                            state.sortColumn = column;
                            state.sortDirection = 'asc';
                        }
                        renderTable();
                    });
                });
            });

            // --- RENDER FUNCTIONS ---
            function renderTable() {
                const tableBody = document.getElementById('userTableBody');
                const paginationControls = document.getElementById('pagination-controls');
                
                // 1. Filter
                let filteredUsers = state.users.filter(user => 
                    user.username.toLowerCase().includes(state.searchQuery)
                );

                // 2. Sort
                filteredUsers.sort((a, b) => {
                    const valA = a[state.sortColumn];
                    const valB = b[state.sortColumn];
                    let comparison = 0;

                    if (state.sortColumn === 'status') {
                        const statusA = new Date(a.valid_until) >= new Date();
                        const statusB = new Date(b.valid_until) >= new Date();
                        comparison = statusA === statusB ? 0 : statusA ? -1 : 1;
                    } else if (typeof valA === 'string') {
                        comparison = valA.localeCompare(valB);
                    } else {
                        comparison = valA - valB;
                    }
                    return state.sortDirection === 'asc' ? comparison : -comparison;
                });

                // 3. Paginate
                const totalPages = Math.ceil(filteredUsers.length / state.itemsPerPage);
                if (state.currentPage > totalPages && totalPages > 0) { state.currentPage = totalPages; }
                const startIndex = (state.currentPage - 1) * state.itemsPerPage;
                const paginatedUsers = filteredUsers.slice(startIndex, startIndex + state.itemsPerPage);

                // 4. Render Rows
                tableBody.innerHTML = paginatedUsers.length > 0 ? paginatedUsers.map(userToRowHtml).join('') : \`<tr><td colspan="7" class="text-center py-8 text-gray-500">No users found.</td></tr>\`;
                
                // 5. Render Pagination
                paginationControls.innerHTML = generatePaginationHtml(filteredUsers.length, totalPages);
                
                // 6. Update Sort Icons
                updateSortIcons();

                // 7. Add event listeners for new elements
                addDynamicEventListeners();
            }

            function userToRowHtml(user) {
                const today = new Date().setHours(0, 0, 0, 0);
                const expiryDate = new Date(user.valid_until).setHours(0, 0, 0, 0);
                const isActive = expiryDate >= today;
                const statusClass = isActive ? 'bg-green-500' : 'bg-red-500';
                const statusText = isActive ? 'Active' : 'Expired';
                const validUntilHtml = isActive ? user.valid_until : \`<span class="font-bold text-red-500">Expired</span>\`;

                return \`
                    <tr class="border-b bg-gray-800 border-gray-700 hover:bg-gray-600">
                        <td class="px-6 py-4"><input type="checkbox" name="usernames" value="\${user.username}" class="user-checkbox"></td>
                        <td class="px-6 py-4 font-mono">\${user.username}</td>
                        <td class="px-6 py-4"><span class="flex items-center"><span class="inline-block w-3 h-3 \${statusClass} rounded-full mr-2"></span>\${statusText}</span></td>
                        <td class="px-6 py-4">\${user.throttle === -1 ? 'Unlimited' : \`\${((user.throttle * 8) / (1024 * 1024)).toFixed(2)} Mbps\`}</td>
                        <td class="px-6 py-4">$ \${(user.bill_amount || 0).toFixed(2)}</td>
                        <td class="px-6 py-4">\${validUntilHtml}</td>
                        <td class="px-6 py-4 text-right">
                            <button onclick="openEditModal('\${user.username}', \${user.throttle}, \${user.bill_amount || 0}, '\${user.valid_until || ''}')" class="font-medium text-blue-500 hover:underline mr-4">Edit</button>
                            <button onclick="confirmDelete('\${user.username}')" class="font-medium text-red-500 hover:underline">Delete</button>
                        </td>
                    </tr>\`;
            }

            function generatePaginationHtml(totalItems, totalPages) {
                if (totalItems === 0) return '';
                const startItem = (state.currentPage - 1) * state.itemsPerPage + 1;
                const endItem = Math.min(startItem + state.itemsPerPage - 1, totalItems);

                const itemsPerPageOptions = [10, 25, 50, 100].map(val => 
                    \`<option value="\${val}" \${state.itemsPerPage === val ? 'selected' : ''}>\${val}</option>\`
                ).join('');

                const pageButtons = totalPages > 1 ? \`
                    <div class="flex items-center gap-2">
                        <button onclick="changePage('prev')" \${state.currentPage === 1 ? 'disabled' : ''} class="px-3 py-1 bg-gray-600 rounded disabled:opacity-50">Prev</button>
                        <span>Page \${state.currentPage} of \${totalPages}</span>
                        <button onclick="changePage('next', \${totalPages})" \${state.currentPage === totalPages ? 'disabled' : ''} class="px-3 py-1 bg-gray-600 rounded disabled:opacity-50">Next</button>
                    </div>
                \` : '';

                return \`
                    <div class="text-sm text-gray-400">
                        Showing <span class="font-medium">\${startItem}</span> to <span class="font-medium">\${endItem}</span> of <span class="font-medium">\${totalItems}</span> results
                    </div>
                    <div class="flex items-center gap-4">
                        <select id="itemsPerPage" class="px-2 py-1 bg-gray-700 border border-gray-600 rounded">\${itemsPerPageOptions}<option value="\${totalItems}" \${state.itemsPerPage === totalItems ? 'selected' : ''}>All</option></select>
                        \${pageButtons}
                    </div>
                \`;
            }
            
            function updateSortIcons() {
                document.querySelectorAll('.sortable').forEach(header => {
                    header.classList.remove('sort-asc', 'sort-desc');
                    const icon = header.querySelector('.sort-icon');
                    if (header.dataset.sort === state.sortColumn) {
                        header.classList.add(state.sortDirection === 'asc' ? 'sort-asc' : 'sort-desc');
                        icon.textContent = state.sortDirection === 'asc' ? '▲' : '▼';
                    } else {
                        icon.textContent = '';
                    }
                });
            }

            // --- DYNAMIC EVENT LISTENERS ---
            function addDynamicEventListeners() {
                // Bulk delete
                const selectAllCheckbox = document.getElementById('selectAllCheckbox');
                const userCheckboxes = document.querySelectorAll('.user-checkbox');
                const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');

                function updateDeleteButtonState() {
                    const anyChecked = [...userCheckboxes].some(cb => cb.checked);
                    bulkDeleteBtn.disabled = !anyChecked;
                }
                
                selectAllCheckbox.addEventListener('change', e => {
                    userCheckboxes.forEach(checkbox => { checkbox.checked = e.target.checked; });
                    updateDeleteButtonState();
                });
                userCheckboxes.forEach(checkbox => {
                    checkbox.addEventListener('change', () => {
                        selectAllCheckbox.checked = userCheckboxes.length > 0 && [...userCheckboxes].every(cb => cb.checked);
                        updateDeleteButtonState();
                    });
                });
                updateDeleteButtonState();

                // Items per page
                const ippSelect = document.getElementById('itemsPerPage');
                if (ippSelect) {
                    ippSelect.addEventListener('change', (e) => {
                        state.itemsPerPage = parseInt(e.target.value, 10);
                        state.currentPage = 1;
                        renderTable();
                    });
                }
            }
            
            function changePage(direction, totalPages) {
                if (direction === 'prev' && state.currentPage > 1) state.currentPage--;
                if (direction === 'next' && state.currentPage < totalPages) state.currentPage++;
                renderTable();
            }

            // --- MODALS and FORMS (mostly unchanged) ---
            const userModal = document.getElementById('userModal'); const form = document.getElementById('userForm'); const title = document.getElementById('modalTitle'); const usernameInput = document.getElementById('username'); const passwordInput = document.getElementById('password'); const passwordHint = document.getElementById('passwordHint'); const editUsernameInput = document.getElementById('editUsername'); const throttleInput = document.getElementById('throttle'); const validUntilInput = document.getElementById('valid_until'); const confirmModal = document.getElementById('confirmModal'); const confirmTitle = document.getElementById('confirmTitle'); const confirmMessage = document.getElementById('confirmMessage'); const confirmOkBtn = document.getElementById('confirmOkBtn'); const confirmCancelBtn = document.getElementById('confirmCancelBtn'); const alertModal = document.getElementById('alertModal'); const alertTitle = document.getElementById('alertTitle'); const alertMessage = document.getElementById('alertMessage'); const alertOkBtn = document.getElementById('alertOkBtn'); let confirmCallback = null;
            function openAddModal() { form.reset(); form.action = '/add-user'; title.textContent = 'Add New User'; usernameInput.disabled = false; editUsernameInput.disabled = true; passwordInput.required = true; passwordHint.textContent = ''; validUntilInput.value = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]; userModal.style.display = 'flex'; }
            function openEditModal(username, throttle, billAmount, validUntil) { form.reset(); form.action = '/edit-user'; title.textContent = 'Edit User: ' + username; usernameInput.value = username; usernameInput.disabled = true; editUsernameInput.value = username; editUsernameInput.disabled = false; passwordInput.placeholder = "Leave blank"; passwordInput.required = false; passwordHint.textContent = '(Leave blank to keep)'; throttleInput.value = throttle === -1 ? -1 : ((throttle * 8) / (1024 * 1024)).toFixed(2); document.getElementById('bill_amount').value = billAmount; validUntilInput.value = validUntil; userModal.style.display = 'flex'; }
            function closeModal(event) { if (!event || event.target === userModal) { userModal.style.display = 'none'; } }
            function addDays(days) { const date = validUntilInput.value ? new Date(validUntilInput.value) : new Date(); date.setDate(date.getDate() + days); validUntilInput.value = date.toISOString().split('T')[0]; }
            form.addEventListener('submit', function(e) {
                // The original input has name="throttle" and a value in Mbps.
                // We must convert this to bytes/sec for the backend.
                // To avoid sending two 'throttle' values (the visible Mbps one and a hidden bytes one),
                // we first create the hidden input with the correct byte value.
                const throttleMbps = parseFloat(throttleInput.value);
                const throttleBytes = throttleMbps === -1 ? -1 : Math.round((throttleMbps * 1024 * 1024) / 8);
                const hiddenInput = document.createElement('input');
                hiddenInput.type = 'hidden';
                hiddenInput.name = 'throttle';
                hiddenInput.value = throttleBytes;
                form.appendChild(hiddenInput);
                
                // Then, we remove the name from the original, visible input so it is not included in the form submission.
                throttleInput.removeAttribute('name');
            });
            function showAlert(message, title = 'Alert') { alertTitle.textContent = title; alertMessage.textContent = message; alertModal.style.display = 'flex'; }
            alertOkBtn.addEventListener('click', () => { alertModal.style.display = 'none'; });
            function showConfirm(title, message, callback) { confirmTitle.textContent = title; confirmMessage.textContent = message; confirmCallback = callback; confirmModal.style.display = 'flex'; }
            function hideConfirm() { confirmModal.style.display = 'none'; confirmCallback = null; }
            confirmOkBtn.addEventListener('click', () => { if (confirmCallback) { confirmCallback(); } hideConfirm(); });
            confirmCancelBtn.addEventListener('click', hideConfirm);
            function confirmDelete(username) { showConfirm('Delete User', \`Delete user "\${username}"?\`, () => { document.getElementById('deleteUsername').value = username; document.getElementById('deleteForm').submit(); }); }
            document.getElementById('bulkDeleteBtn').addEventListener('click', async () => { const selectedUsers = [...document.querySelectorAll('.user-checkbox:checked')].map(cb => cb.value); if (selectedUsers.length === 0) return; showConfirm('Delete Users', \`Delete \${selectedUsers.length} selected user(s)?\`, async () => { try { const res = await fetch('/delete-users', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ 'usernames': selectedUsers }) }); if (res.ok) { window.location.reload(); } else { const err = await res.json(); showAlert('Error: ' + (err.message || 'Unknown error')); } } catch (error) { showAlert('Network error.'); } }); });
        </script>
    </body>
    </html>
    `;
}

// --- START SERVER ---
initializeDatabase().then(() => {
    server.listen(PROXY_PORT, '0.0.0.0', () => { log(`Multi-protocol proxy server listening on port ${PROXY_PORT}`); });
    adminServer.listen(ADMIN_PORT, '0.0.0.0', () => {
        log(`Admin panel listening on http://localhost:${ADMIN_PORT}`);
        log(`Admin User: ${ADMIN_USERNAME}`);
        log('Users loaded: ' + Object.keys(users).join(', '));
    });
}).catch(err => { console.error('Failed to initialize and start the server:', err); process.exit(1); });

server.on('error', (err) => {
    console.error(`Server error: ${err.message}`);
    if (err.code === 'EADDRINUSE') { console.error(`Port ${PROXY_PORT} is already in use.`); }
});


