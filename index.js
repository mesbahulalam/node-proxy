/*
 * Multi-Protocol Proxy Server (SOCKS4, SOCKS5, HTTP) with User Management and Bandwidth Throttling
 *
 * Description:
 * This Node.js script creates a proxy server that handles SOCKS4, SOCKS5, and HTTP requests.
 * It features a persistent user management system using SQLite and per-user bandwidth throttling.
 *
 * Features:
 * - Supports SOCKSv4, SOCKSv5, and HTTP/HTTPS (CONNECT) protocols.
 * - Protocol auto-detection on a single port.
 * - User/password authentication for SOCKS5 and HTTP.
 * - Per-user bandwidth throttling (rate limiting).
 * - Persistent user database using SQLite.
 * - Easy initial user configuration in the script.
 *
 * How to Run:
 * 1. Save this code as `proxy.js`.
 * 2. Install the required dependency: `npm install sqlite3`
 * 3. Configure the `PROXY_PORT` and `initialUsers` object below.
 * 4. Run from your terminal: `node proxy.js`
 *
 * How to Configure Users:
 * - The `initialUsers` object is used to populate the database (`proxy_users.db`) ONLY if it's empty.
 * - To add/remove/update users after the first run, you will need to use an SQLite database browser.
 * - `password`: The user's password for authentication.
 * - `throttle`: The maximum bandwidth in bytes per second. Use -1 for unlimited speed.
 *
 * Example User Configuration:
 * 'user1': { password: 'password123', throttle: 100 * 1024 }, // 100 KB/s
 * 'admin': { password: 'supersecret', throttle: -1 }, // Unlimited speed
 */

const net = require('net');
const dns = require('dns');
const { Buffer } = require('buffer');
const { Duplex } = require('stream');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const querystring = require('querystring');

// --- CONFIGURATION ---

const PROXY_PORT = 8080;
const ADMIN_PORT = 8081; // Port for the web admin panel
const DB_FILE = './proxy_users.db';
const ALLOW_UNAUTHENTICATED = false; // If true, allows connections without a valid user. They will have unlimited bandwidth.

// --- Admin Panel Credentials ---
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'changeme'; // IMPORTANT: Change this password!

// This list is used to populate the DB only on the first run.
const initialUsers = {
    'demo': {
        password: 'password123',
        throttle: 250 * 1024 // 250 KB/s
    },
    'poweruser': {
        password: 'strongpassword',
        throttle: 2 * 1024 * 1024 // 2 MB/s
    },
    'unlimited': {
        password: 'freeuser',
        throttle: -1, // -1 means unlimited speed
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
            db.run(`CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                throttle INTEGER NOT NULL
            )`, (err) => {
                if (err) return reject(err);
                log('Users table checked/created.');
            });

            db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
                if (err) return reject(err);
                if (row.count === 0) {
                    log('Users table is empty. Populating with initial users...');
                    const stmt = db.prepare('INSERT INTO users (username, password, throttle) VALUES (?, ?, ?)');
                    for (const username in initialUsers) {
                        const user = initialUsers[username];
                        stmt.run(username, user.password, user.throttle);
                    }
                    stmt.finalize((err) => {
                        if (err) return reject(err);
                        log('Initial users have been added to the database.');
                        loadUsersFromDb().then(resolve).catch(reject);
                    });
                } else {
                    loadUsersFromDb().then(resolve).catch(reject);
                }
            });
        });
    });
}

function loadUsersFromDb() {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM users', (err, rows) => {
            if (err) return reject(err);
            
            // Clear the old cache before reloading
            const newUsers = {};
            rows.forEach(row => {
                newUsers[row.username] = {
                    password: row.password,
                    throttle: row.throttle
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
        if (!this.isProcessing) {
            this._processBuffer();
        }
    }

    _read(size) {
        // Data is pushed downstream, so we don't need to implement _read.
    }

    _processBuffer() {
        if (this.buffer.length === 0) {
            this.isProcessing = false;
            return;
        }

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
    return users[username] || null;
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
        
        if (protocolByte === 0x05) {
            handleSocks5(clientSocket, initialData);
        } else if (protocolByte === 0x04) {
            handleSocks4(clientSocket, initialData);
        } else {
            handleHttp(clientSocket, initialData);
        }
    });

    clientSocket.on('error', (err) => {
        log(`Client socket error: ${err.message}`);
        clientSocket.destroy();
    });

    clientSocket.on('close', () => {
        log(`Client disconnected`);
    });
});


// --- PROTOCOL HANDLERS (Unchanged) ---

/**
 * Handles SOCKS5 protocol negotiation and connection.
 */
function handleSocks5(clientSocket, initialData) {
    log('SOCKS5 protocol detected');
    let user = null;
    let state = 'handshake';

    // Step 1: Client Greeting
    const nmethods = initialData[1];
    const methods = initialData.slice(2, 2 + nmethods);
    
    let authMethod = 0xFF; // No acceptable method by default

    // Prioritize User/Pass if client supports it
    if (methods.includes(0x02)) {
        authMethod = 0x02;
    } 
    // Fallback to No Auth only if it's allowed by config and supported by client
    else if (ALLOW_UNAUTHENTICATED && methods.includes(0x00)) {
        authMethod = 0x00;
    }
    
    if (authMethod === 0xFF) {
        log('SOCKS5: No acceptable authentication method. Server requires authentication. Closing connection.');
        clientSocket.end(Buffer.from([0x05, 0xFF]));
        return;
    }

    clientSocket.write(Buffer.from([0x05, authMethod]));

    if (authMethod === 0x00) {
        state = 'request';
    } else if (authMethod === 0x02) {
        state = 'authentication';
    }
    
    clientSocket.on('data', socks5Handler);

    function socks5Handler(data) {
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
                log(`SOCKS5: User '${username}' authentication failed.`);
                clientSocket.end(Buffer.from([0x01, 0x01])); // Auth failure
            }
            return;
        }

        if (state === 'request') {
            const [ver, cmd, rsv, atyp] = data;
            
            if (ver !== 0x05 || cmd !== 0x01) {
                log(`SOCKS5: Unsupported command: ${cmd}`);
                clientSocket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
                return;
            }

            let host, port, addrEndOffset;

            if (atyp === 0x01) { // IPv4
                host = data.slice(4, 8).join('.');
                port = data.readUInt16BE(8);
                addrEndOffset = 10;
            } else if (atyp === 0x03) { // Domain name
                const hostLen = data[4];
                host = data.slice(5, 5 + hostLen).toString('utf8');
                port = data.readUInt16BE(5 + hostLen);
                addrEndOffset = 5 + hostLen + 2;
            } else if (atyp === 0x04) { // IPv6
                host = data.slice(4, 20).toString('hex').match(/.{1,4}/g).join(':');
                port = data.readUInt16BE(20);
                addrEndOffset = 22;
            } else {
                log(`SOCKS5: Unsupported address type: ${atyp}`);
                clientSocket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
                return;
            }
            
            log(`SOCKS5: Connecting to ${host}:${port}`);
            clientSocket.removeListener('data', socks5Handler);
            
            createRemoteConnection(clientSocket, user, host, port, (remoteSocket) => {
                const reply = Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                clientSocket.write(reply);
                
                pipeData(clientSocket, remoteSocket, user, `SOCKS5 (${user ? user.username : 'no-auth'})`);
                
                const remainingData = data.slice(addrEndOffset);
                if (remainingData.length > 0) {
                     remoteSocket.write(remainingData);
                }
            }, (err) => {
                log(`SOCKS5: Connection to ${host}:${port} failed: ${err.message}`);
                const reply = Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                clientSocket.end(reply);
            });
        }
    }
}

/**
 * Handles SOCKS4 protocol connection.
 */
function handleSocks4(clientSocket, initialData) {
    log('SOCKS4 protocol detected');
    const cmd = initialData[1];
    if (cmd !== 0x01) {
        log(`SOCKS4: Unsupported command: ${cmd}`);
        clientSocket.end(Buffer.from([0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        return;
    }

    const port = initialData.readUInt16BE(2);
    let ip = initialData.slice(4, 8).join('.');
    const nullByteIndex = initialData.indexOf(0x00, 8);
    const userId = initialData.slice(8, nullByteIndex).toString('utf8');
    
    const user = findUser(userId); 
    log(`SOCKS4: Attempting connection for user '${userId}'`);
    if(!user) {
        log(`SOCKS4: User '${userId}' not found or configured.`);
        if (!ALLOW_UNAUTHENTICATED) {
            log('SOCKS4: Unauthenticated access denied by server configuration.');
            clientSocket.end(Buffer.from([0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // Request rejected
            return;
        }
    }

    let host = ip;
    if (initialData[4] === 0 && initialData[5] === 0 && initialData[6] === 0 && initialData[7] !== 0) {
        const domainNullByteIndex = initialData.indexOf(0x00, nullByteIndex + 1);
        host = initialData.slice(nullByteIndex + 1, domainNullByteIndex).toString('utf8');
    }

    log(`SOCKS4: Connecting to ${host}:${port}`);
    createRemoteConnection(clientSocket, user, host, port, (remoteSocket) => {
        clientSocket.write(Buffer.from([0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        pipeData(clientSocket, remoteSocket, user, `SOCKS4 (${userId})`);
    }, (err) => {
        log(`SOCKS4: Connection to ${host}:${port} failed: ${err.message}`);
        clientSocket.end(Buffer.from([0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    });
}

/**
 * Handles HTTP/HTTPS proxy requests.
 */
function handleHttp(clientSocket, initialData) {
    log('HTTP protocol detected');
    const requestStr = initialData.toString('utf8');
    const [requestLine] = requestStr.split('\r\n');
    const [method, url, version] = requestLine.split(' ');

    if (!method || !url || !version) {
        log('HTTP: Malformed request. Closing connection.');
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
            log(`HTTP: User '${username}' authentication failed.`);
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
            log(`HTTPS CONNECT: Connection to ${host}:${port} failed: ${err.message}`);
            clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}`);
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
                log(`HTTP ${method}: Connection to ${host}:${port} failed: ${err.message}`);
                clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}`);
            });
        } catch (error) {
            log(`HTTP: Invalid URL: ${url}. Error: ${error.message}`);
            clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\nInvalid URL');
        }
    }
}

// --- UTILITY FUNCTIONS ---

/**
 * Creates a connection to the target remote server.
 */
function createRemoteConnection(clientSocket, user, host, port, successCallback, errorCallback) {
    dns.lookup(host, (err, address) => {
        if (err) {
            return errorCallback(err);
        }
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

/**
 * Pipes data between two sockets, applying throttling if necessary.
 */
function pipeData(clientSocket, remoteSocket, user, connectionType) {
    const userLabel = user ? user.username : 'unauthenticated';
    const throttleRate = user ? user.throttle : -1;

    log(`Piping data for ${connectionType} connection. User: ${userLabel}. Throttle: ${throttleRate === -1 ? 'Unlimited' : `${throttleRate / 1024} KB/s`}`);
    
    if (throttleRate > 0) {
        // Apply throttling
        const clientToRemoteThrottler = new ThrottledStream(throttleRate);
        const remoteToClientThrottler = new ThrottledStream(throttleRate);

        clientSocket.pipe(clientToRemoteThrottler).pipe(remoteSocket);
        remoteSocket.pipe(remoteToClientThrottler).pipe(clientSocket);
    } else {
        // No throttling, direct pipe for maximum performance
        clientSocket.pipe(remoteSocket);
        remoteSocket.pipe(clientSocket);
    }
    
    clientSocket.on('close', () => remoteSocket.destroy());
    remoteSocket.on('close', () => clientSocket.destroy());
    clientSocket.on('error', (err) => log(`Client pipe error for ${userLabel}: ${err.message}`));
    remoteSocket.on('error', (err) => log(`Remote pipe error for ${userLabel}: ${err.message}`));
}

function log(message) {
    console.log(`[${new Date().toISOString()}] ${message}`);
}


// --- ADMIN PANEL SERVER ---

const adminServer = http.createServer(async (req, res) => {
    try {
        // Basic session management
        const cookies = querystring.parse(req.headers.cookie, '; ');
        const sessionId = cookies.sessionId || '';
        const isAuthenticated = sessionStore[sessionId];

        if (req.url === '/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', () => {
                const { username, password } = querystring.parse(body);
                if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
                    const newSessionId = require('crypto').randomBytes(16).toString('hex');
                    sessionStore[newSessionId] = true;
                    res.writeHead(302, {
                        'Set-Cookie': `sessionId=${newSessionId}; HttpOnly; Path=/`,
                        'Location': '/'
                    });
                    res.end();
                } else {
                    res.writeHead(302, { 'Location': '/?error=1' });
                    res.end();
                }
            });
            return;
        }

        if (req.url === '/logout') {
            delete sessionStore[sessionId];
            res.writeHead(302, {
                'Set-Cookie': `sessionId=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
                'Location': '/'
            });
            res.end();
            return;
        }
        
        if (!isAuthenticated) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(getLoginPage(req.url.includes('error=1')));
            return;
        }

        // --- Authenticated Routes ---
        if (req.url === '/') {
             db.all('SELECT username, throttle FROM users ORDER BY username', (err, userList) => {
                if(err) {
                    res.writeHead(500);
                    return res.end('Error fetching users');
                }
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(getDashboardPage(userList));
            });
        } else if (req.url === '/add-user' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                const { username, password, throttle } = querystring.parse(body);
                db.run('INSERT INTO users (username, password, throttle) VALUES (?, ?, ?)', [username, password, parseInt(throttle, 10)], async function(err) {
                    await loadUsersFromDb();
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                });
            });
        } else if (req.url === '/edit-user' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                const { username, password, throttle } = querystring.parse(body);
                const query = password ? 'UPDATE users SET password = ?, throttle = ? WHERE username = ?' : 'UPDATE users SET throttle = ? WHERE username = ?';
                const params = password ? [password, parseInt(throttle, 10), username] : [parseInt(throttle, 10), username];
                db.run(query, params, async function(err) {
                    await loadUsersFromDb();
                    res.writeHead(302, { 'Location': '/' });
                    res.end();
                });
            });
        } else if (req.url === '/delete-user' && req.method === 'POST') {
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

function getLoginPage(error = false) {
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

function getDashboardPage(userList) {
    const userRows = userList.map(user => `
        <tr class="border-b bg-gray-800 border-gray-700 hover:bg-gray-600">
            <td class="px-6 py-4 font-mono">${user.username}</td>
            <td class="px-6 py-4">${user.throttle === -1 ? 'Unlimited' : `${(user.throttle / 1024).toFixed(1)} KB/s`}</td>
            <td class="px-6 py-4 text-right">
                <button onclick="openEditModal('${user.username}', ${user.throttle})" class="font-medium text-blue-500 hover:underline mr-4">Edit</button>
                <button onclick="confirmDelete('${user.username}')" class="font-medium text-red-500 hover:underline">Delete</button>
            </td>
        </tr>
    `).join('');

    return `
    <!DOCTYPE html>
    <html lang="en" class="bg-gray-900 text-white">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="p-4 sm:p-6 md:p-8">
        <div class="max-w-6xl mx-auto">
            <header class="flex items-center justify-between mb-8">
                <h1 class="text-3xl font-bold">Proxy User Management</h1>
                <div>
                    <button onclick="openAddModal()" class="px-5 py-2.5 text-base font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 focus:ring-4 focus:ring-blue-800 mr-4">Add User</button>
                    <a href="/logout" class="px-5 py-2.5 text-base font-medium text-white bg-gray-600 rounded-lg hover:bg-gray-700 focus:ring-4 focus:ring-gray-800">Logout</a>
                </div>
            </header>
            
            <div class="relative overflow-x-auto shadow-md sm:rounded-lg">
                <table class="w-full text-sm text-left text-gray-400">
                    <thead class="text-xs uppercase bg-gray-700 text-gray-400">
                        <tr>
                            <th scope="col" class="px-6 py-3">Username</th>
                            <th scope="col" class="px-6 py-3">Bandwidth Throttle</th>
                            <th scope="col" class="px-6 py-3"><span class="sr-only">Actions</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${userRows}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Add/Edit Modal -->
        <div id="userModal" class="fixed inset-0 z-50 items-center justify-center hidden bg-black bg-opacity-75" onclick="closeModal(event)">
            <div class="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg" onclick="event.stopPropagation()">
                <h3 id="modalTitle" class="text-2xl font-bold">Add New User</h3>
                <form id="userForm" action="/add-user" method="POST" class="space-y-4">
                    <input type="hidden" name="username" id="editUsername">
                    <div>
                        <label for="username" class="block mb-2 text-sm font-medium text-gray-300">Username</label>
                        <input type="text" name="username" id="username" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" required>
                    </div>
                    <div>
                        <label for="password" class="block mb-2 text-sm font-medium text-gray-300">Password <span id="passwordHint" class="text-xs text-gray-400"></span></label>
                        <input type="password" name="password" id="password" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label for="throttle" class="block mb-2 text-sm font-medium text-gray-300">Throttle (in KB/s, -1 for unlimited)</label>
                        <input type="number" name="throttle" id="throttle" class="w-full px-4 py-2 text-white bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" value="-1" required>
                    </div>
                    <div class="flex justify-end gap-4 pt-4">
                        <button type="button" onclick="closeModal()" class="px-5 py-2.5 text-base font-medium text-gray-300 bg-gray-700 rounded-lg hover:bg-gray-600">Cancel</button>
                        <button type="submit" class="px-5 py-2.5 text-base font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700">Save User</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Delete Form (hidden) -->
        <form id="deleteForm" action="/delete-user" method="POST" style="display: none;">
            <input type="hidden" name="username" id="deleteUsername">
        </form>

        <script>
            const modal = document.getElementById('userModal');
            const form = document.getElementById('userForm');
            const title = document.getElementById('modalTitle');
            const usernameInput = document.getElementById('username');
            const passwordInput = document.getElementById('password');
            const passwordHint = document.getElementById('passwordHint');
            const throttleInput = document.getElementById('throttle');
            const editUsernameInput = document.getElementById('editUsername');
            
            function openAddModal() {
                form.reset();
                form.action = '/add-user';
                title.textContent = 'Add New User';
                usernameInput.disabled = false;
                passwordInput.required = true;
                passwordHint.textContent = '';
                modal.style.display = 'flex';
            }

            function openEditModal(username, throttle) {
                form.reset();
                form.action = '/edit-user';
                title.textContent = 'Edit User: ' + username;
                
                usernameInput.value = username;
                usernameInput.disabled = true;
                editUsernameInput.value = username;
                
                passwordInput.placeholder = "Leave blank to keep unchanged";
                passwordInput.required = false;
                passwordHint.textContent = '(Leave blank to keep unchanged)';

                throttleInput.value = throttle === -1 ? -1 : (throttle / 1024);
                
                modal.style.display = 'flex';
            }

            function closeModal(event) {
                if (!event || event.target === modal) {
                    modal.style.display = 'none';
                }
            }

            function confirmDelete(username) {
                if (confirm('Are you sure you want to delete user "' + username + '"?')) {
                    document.getElementById('deleteUsername').value = username;
                    document.getElementById('deleteForm').submit();
                }
            }
            
            // Convert throttle to bytes before submit
            form.addEventListener('submit', function(e) {
                const throttleKb = parseInt(throttleInput.value, 10);
                const throttleBytes = throttleKb === -1 ? -1 : throttleKb * 1024;
                
                const hiddenInput = document.createElement('input');
                hiddenInput.type = 'hidden';
                hiddenInput.name = 'throttle';
                hiddenInput.value = throttleBytes;
                form.appendChild(hiddenInput);

                // Re-enable username for submission if it's an edit form
                if (usernameInput.disabled) {
                    usernameInput.disabled = false;
                }
            });

        </script>
    </body>
    </html>
    `;
}


// --- START SERVER ---

initializeDatabase()
    .then(() => {
        // Start the main proxy server
        server.listen(PROXY_PORT, '0.0.0.0', () => {
            log(`Multi-protocol proxy server listening on port ${PROXY_PORT}`);
        });

        // Start the admin panel server
        adminServer.listen(ADMIN_PORT, '0.0.0.0', () => {
            log(`Admin panel listening on http://localhost:${ADMIN_PORT}`);
            log(`Admin User: ${ADMIN_USERNAME}`);
            log('Users loaded: ' + Object.keys(users).join(', '));
        });
    })
    .catch(err => {
        console.error('Failed to initialize and start the server:', err);
        process.exit(1);
    });

server.on('error', (err) => {
    console.error(`Server error: ${err.message}`);
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PROXY_PORT} is already in use. Please choose a different port.`);
    }
});



