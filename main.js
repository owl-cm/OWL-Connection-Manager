/*
 * OWL - Connection Manager
 * Copyright (C) 2025 Mohamed AZGHARI
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const os = require('os');
const pty = require('node-pty');
const fs = require('fs');
const { Client } = require('ssh2');
const crypto = require('crypto');

// --- Crypto Helpers ---
const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 64;
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const ITERATIONS = 100000;

let vaultKey = null; // Stores the derived key in memory when unlocked
let vaultSalt = null; // Stores the salt to ensure consistent exports

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, 'sha512');
}

function encrypt(text, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    content: encrypted
  };
}

function decrypt(encryptedData, key) {
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const tag = Buffer.from(encryptedData.tag, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encryptedData.content, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}


// Helper to escape shell arguments for remote commands
function escapeShellArg(arg) {
  if (typeof arg !== 'string') return '';
  return `'${arg.replace(/'/g, "'\\''")}'`;
}


let mainWindow;
const terminals = {};
const sftpConnections = {}; // { conn, sftp, ready, queue: [], runningCount: 0 }

const connectionPromises = {};

async function getRawConnection(connection) {
  const key = `${connection.user}@${connection.host}:${connection.port || 22}`;

  if (sftpConnections[key] && sftpConnections[key].ready) {
    return sftpConnections[key];
  }

  if (connectionPromises[key]) {
    return connectionPromises[key];
  }

  // Rate Limiting
  const now = Date.now();
  if (!global.connectionRateLimits) global.connectionRateLimits = {};
  const lastAttempt = global.connectionRateLimits[key] || 0;

  if (now - lastAttempt < 5000) { // 5 seconds cooldown
    const err = new Error('Connection rate limit exceeded. Please wait.');
    console.error(`[SSH] Rate limit hit for ${key}`);
    return Promise.reject(err);
  }
  global.connectionRateLimits[key] = now;

  console.log(`[SSH] Connecting to ${key}...`);
  connectionPromises[key] = new Promise((resolve, reject) => {

    const startTargetConnection = (sock = undefined, bastionClient = undefined) => {
      const conn = new Client();
      conn.on('ready', () => {
        console.log(`[SSH] Connected to ${key}`);
        const session = {
          conn,
          bastionClient,
          ready: true,
          queue: [],
          runningCount: 0,
          key: key
        };
        sftpConnections[key] = session;
        delete connectionPromises[key];
        resolve(session);
      }).on('error', (err) => {
        console.error(`[SSH] Connection error ${key}:`, err.message);
        if (bastionClient) bastionClient.end();
        delete sftpConnections[key];
        delete connectionPromises[key];
        reject(err);
      }).on('end', () => {
        console.log(`[SSH] Connection ended ${key}`);
        if (bastionClient) bastionClient.end();
        delete sftpConnections[key];
      }).on('close', () => {
        console.log(`[SSH] Connection closed ${key}`);
        if (bastionClient) bastionClient.end();
        delete sftpConnections[key];
      }).connect({
        host: connection.host,
        port: connection.port || 22,
        username: connection.user,
        password: connection.authType === 'key' ? undefined : connection.password,
        privateKey: (connection.authType === 'key' && connection.keyPath && fs.existsSync(connection.keyPath)) ? fs.readFileSync(connection.keyPath) : undefined,
        passphrase: connection.authType === 'key' ? connection.passphrase : undefined,
        readyTimeout: 30000,
        keepaliveInterval: 10000,
        keepaliveCountMax: 3,
        sock: sock
      });
    };

    if (connection.bastionHost) {
      console.log(`[SSH] Connecting via Bastion: ${connection.bastionHost}`);
      const bastion = new Client();
      bastion.on('ready', () => {
        bastion.forwardOut('127.0.0.1', 12345, connection.host, connection.port || 22, (err, stream) => {
          if (err) {
            bastion.end();
            delete connectionPromises[key];
            return reject(new Error(`Bastion forwarding failed: ${err.message}`));
          }
          startTargetConnection(stream, bastion);
        });
      }).on('error', (err) => {
        console.error(`[SSH] Bastion connection error:`, err.message);
        delete connectionPromises[key];
        reject(new Error(`Bastion connection failed: ${err.message}`));
      }).connect({
        host: connection.bastionHost,
        username: connection.bastionUser || connection.user,
        privateKey: (connection.bastionKeyPath && fs.existsSync(connection.bastionKeyPath)) ? fs.readFileSync(connection.bastionKeyPath) : undefined,
        readyTimeout: 30000
      });
    } else {
      startTargetConnection();
    }
  });

  return connectionPromises[key];
}

// SSH Command Queue to prevent "Channel open failure"
async function execQueued(connection, cmd, options = {}) {
  const session = await getRawConnection(connection);

  // Max concurrent channels per connection
  const MAX_CONCURRENT = 2;

  return new Promise((resolve, reject) => {
    const task = async () => {
      session.runningCount++;
      let isDone = false;

      const cleanup = (result, error) => {
        if (isDone) return;
        isDone = true;
        session.runningCount--;
        if (error) reject(error);
        else resolve(result);

        // Process next task in queue
        process.nextTick(() => processQueue(session));
      };

      try {
        session.conn.exec(cmd, options, (err, stream) => {
          if (err) {
            return cleanup(null, err);
          }

          let data = '';
          let stderr = '';

          if (options.onStream) {
            options.onStream(stream);
          }

          stream.on('data', (d) => { data += d.toString(); });
          if (stream.stderr) {
            stream.stderr.on('data', (d) => { stderr += d.toString(); });
          }

          stream.on('close', (code) => {
            cleanup({ code, data, stderr });
          });

          stream.on('error', (err) => {
            cleanup(null, err);
          });
        });

        // Safety timeout for the command itself (30 seconds)
        setTimeout(() => {
          if (!isDone) {
            cleanup(null, new Error('Command timed out after 30s'));
          }
        }, options.timeout || 30000);

      } catch (err) {
        cleanup(null, err);
      }
    };

    session.queue.push(task);
    processQueue(session);
  });

  function processQueue(session) {
    while (session.runningCount < MAX_CONCURRENT && session.queue.length > 0) {
      const nextTask = session.queue.shift();
      nextTask();
    }
  }
}


function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    title: 'OWL',
    icon: path.join(__dirname, 'owl_logo.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      sandbox: false,
      enableRemoteModule: false
    },

    backgroundColor: '#1e1e1e',
  });


  mainWindow.maximize();

  // Security Headers
  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'"],
        'X-Content-Type-Options': ['nosniff'],
        'X-Frame-Options': ['DENY']
      }
    });
  });

  mainWindow.loadFile('index.html');

  mainWindow.on('closed', function () {
    mainWindow = null;
  });

}

app.on('ready', () => {
  createWindow();
  // Initial log rotation check (default 100MB if not specified)
  rotateLogs(100);
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', function () {
  if (mainWindow === null) createWindow();
});

// IPC Handlers

// Vault Management
ipcMain.handle('check-vault-status', async () => {
  const connectionsPath = path.join(app.getPath('userData'), 'connections.json');
  if (!fs.existsSync(connectionsPath)) {
    return 'uninitialized';
  }
  try {
    const raw = fs.readFileSync(connectionsPath, 'utf8');
    const data = JSON.parse(raw);
    // Check if it's already encrypted format
    if (data.salt && data.iv && data.content) {
      return vaultKey ? 'unlocked' : 'locked';
    }
    return 'plaintext'; // Legacy data needs migration
  } catch (e) {
    return 'uninitialized';
  }
});

ipcMain.handle('log', (event, message) => {
  console.log('[Renderer]', message);
});

ipcMain.handle('setup-vault', async (event, password) => {
  const connectionsPath = path.join(app.getPath('userData'), 'connections.json');
  let initialData = [];

  // Check for existing plaintext data to migrate
  if (fs.existsSync(connectionsPath)) {
    try {
      const raw = fs.readFileSync(connectionsPath, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) {
        initialData = data;
      }
    } catch (e) {
      console.error('Failed to read existing data for migration');
    }
  }



  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(password, salt);
  vaultKey = key; // Unlock immediately
  vaultSalt = salt;

  const encrypted = encrypt(JSON.stringify(initialData), key);

  const vaultData = {
    version: 1,
    salt: salt.toString('hex'),
    iv: encrypted.iv,
    tag: encrypted.tag,
    content: encrypted.content
  };

  fs.writeFileSync(connectionsPath, JSON.stringify(vaultData, null, 2));
  return true;
});

ipcMain.handle('unlock-vault', async (event, password) => {
  const connectionsPath = path.join(app.getPath('userData'), 'connections.json');
  try {
    const raw = fs.readFileSync(connectionsPath, 'utf8');
    const vaultData = JSON.parse(raw);

    if (!vaultData.salt || !vaultData.content) return false;

    const salt = Buffer.from(vaultData.salt, 'hex');
    const key = deriveKey(password, salt);

    // Verify key by attempting to decrypt
    try {
      decrypt(vaultData, key);
      vaultKey = key; // Success, store key
      vaultSalt = salt;
      return true;
    } catch (e) {
      return false; // Wrong password
    }
  } catch (e) {
    return false;
  }
});

ipcMain.handle('reset-vault', async () => {
  const connectionsPath = path.join(app.getPath('userData'), 'connections.json');
  if (fs.existsSync(connectionsPath)) {
    fs.unlinkSync(connectionsPath);
  }
  vaultKey = null;
  vaultSalt = null;
  return true;
});

ipcMain.handle('lock-vault', async () => {
  vaultKey = null;
  vaultSalt = null;
  return true;
});

// Load connections
ipcMain.handle('load-connections', async () => {
  const connectionsPath = path.join(app.getPath('userData'), 'connections.json');
  if (!fs.existsSync(connectionsPath)) {
    return [];
  }
  try {
    const raw = fs.readFileSync(connectionsPath, 'utf8');
    const data = JSON.parse(raw);

    // Handle Plaintext (Legacy)
    if (Array.isArray(data)) {
      return data;
    }

    // Handle Encrypted
    if (data.salt && data.content) {
      if (!vaultKey) {
        throw new Error('Vault is locked');
      }
      const decrypted = decrypt(data, vaultKey);
      return JSON.parse(decrypted);
    }

    return [];
  } catch (e) {
    console.error('Failed to load connections');
    return [];
  }
});

// Save connections
// Save connections
ipcMain.handle('save-connections', async (event, connections) => {
  const connectionsPath = path.join(app.getPath('userData'), 'connections.json');
  try {
    if (vaultKey) {
      // Encrypted Save
      // We need to read the salt from the file to keep it consistent, or generate new?
      // Actually, we can just regenerate everything since we have the key.
      // Wait, we need the SALT to derive the key next time. 
      // If we have vaultKey, we don't know the salt unless we stored it.
      // Let's read the existing salt if possible, or we need to store salt in memory too.

      // Better: Read existing file to get salt, or store salt in memory.
      // Let's modify unlock/setup to store salt? 
      // Or just read the file, parse it, update content/iv/tag, keep salt.

      let saltHex;
      if (fs.existsSync(connectionsPath)) {
        const raw = fs.readFileSync(connectionsPath, 'utf8');
        const oldData = JSON.parse(raw);
        saltHex = oldData.salt;
      }

      // If no salt (shouldn't happen if unlocked), we have a problem.
      // But wait, if we are saving, we must be unlocked.
      // If we migrated from plaintext, we just created a new file.

      // Let's just re-encrypt. But we need the SALT to be saved.
      // We can't easily reverse Key -> Salt.
      // So we must ensure we preserve the salt from the file.

      if (!saltHex) {
        // This case implies we are saving but don't have the salt. 
        // This might happen if we just migrated? No, setup-vault writes the file.
        // So reading the file is safe.
        console.error('Critical: Cannot find salt for encryption');
        return false;
      }

      const encrypted = encrypt(JSON.stringify(connections), vaultKey);
      const vaultData = {
        version: 1,
        salt: saltHex,
        iv: encrypted.iv,
        tag: encrypted.tag,
        content: encrypted.content
      };
      fs.writeFileSync(connectionsPath, JSON.stringify(vaultData, null, 2));

    } else {
      // Fallback for plaintext (should not happen if we force vault)
      // Or maybe user hasn't set up vault yet?
      // If we want to enforce encryption, we should force setup.
      // For now, if no key, save as plaintext (legacy behavior)
      fs.writeFileSync(connectionsPath, JSON.stringify(connections, null, 2));
    }
    return true;
  } catch (e) {
    console.error('Failed to save connections', e);
    return false;
  }
});

// Terminal handling
ipcMain.on('terminal-create', (event, { connection, cols, rows }) => {
  // Construct SSH command directly to avoid shell injection
  let spawnShell = 'bash';
  let spawnArgs = [];

  if (connection) {
    spawnShell = 'ssh';

    // Identity
    if (connection.authType === 'key' && connection.keyPath) {
      spawnArgs.push('-i', connection.keyPath);
    }

    // Port
    spawnArgs.push('-p', (connection.port || 22).toString());

    // Bastion - Use ProxyJump instead of ProxyCommand to prevent command injection
    if (connection.bastionHost) {
      const bUser = connection.bastionUser || connection.user;
      const bHost = connection.bastionHost;

      // Use -J (ProxyJump) which is safer than ProxyCommand
      spawnArgs.push('-J', `${bUser}@${bHost}`);

      // Add bastion key if specified
      if (connection.bastionKeyPath) {
        // Note: SSH doesn't support per-jump-host keys via -J
        // For complex bastion scenarios, consider using SSH config file
        console.warn('Bastion key path specified but -J does not support per-host keys. Consider using ~/.ssh/config');
      }
    }

    spawnArgs.push(`${connection.user}@${connection.host}`);
  }

  const ptyProcess = pty.spawn(spawnShell, spawnArgs, {

    name: 'xterm-color',
    cols: cols || 80,
    rows: rows || 30,
    cwd: process.env.HOME,
    env: process.env
  });

  const pid = ptyProcess.pid;
  console.log(`[Terminal] Created PTY for PID ${pid} (${cols}x${rows})`);
  terminals[pid] = ptyProcess;

  // Password Auto-login Logic
  let passwordSent = false;
  let buffer = ''; // Buffer to handle split chunks

  ptyProcess.onData((data) => {
    // Accumulate data to handle split chunks
    buffer += data;

    // Limit buffer size to prevent memory issues
    if (buffer.length > 1000) {
      buffer = buffer.slice(-1000);
    }

    if (connection) {
      // Handle Fingerprint confirmation
      if (buffer.includes('Are you sure you want to continue connecting') && (buffer.includes('yes/no') || buffer.includes('[yes/no]'))) {
        console.log('Detected fingerprint confirmation, sending "yes"...');
        ptyProcess.write('yes\n');
        buffer = '';
      }

      // Handle Password / Passphrase
      const passwordRegex = /(password|passphrase|verification code|token|password for .*):?\s*$/i;
      const trimmedBuffer = buffer.trim();
      if (passwordRegex.test(trimmedBuffer)) {
        const isPassphrase = trimmedBuffer.toLowerCase().includes('passphrase');
        const secret = isPassphrase ? connection.passphrase : connection.password;

        if (secret) {
          console.log(`Detected ${isPassphrase ? 'passphrase' : 'password'} prompt, sending secret...`);
          setTimeout(() => {
            ptyProcess.write(secret + '\n');
            buffer = '';
          }, 200);
        }
      }

      // Heuristic to detect shell prompt
      if (!passwordSent && (buffer.includes('$ ') || buffer.includes('# ') || buffer.includes('> ') || buffer.includes('] '))) {
        console.log('Shell prompt detected.');
        passwordSent = true;
      }
    }

    if (logStreams[pid]) {
      logStreams[pid].write(data);
    }
    event.sender.send('terminal-incoming', { pid, data });
  });

  event.sender.send('terminal-created', { pid });

  // Cleanup on exit
  ptyProcess.onExit(() => {
    delete terminals[pid];
    event.sender.send('terminal-exited', { pid });
  });
});

ipcMain.on('terminal-write', (event, { pid, data }) => {
  if (terminals[pid]) {
    terminals[pid].write(data);
  }
});

ipcMain.on('terminal-resize', (event, { pid, cols, rows }) => {
  if (terminals[pid]) {
    console.log(`[Terminal] Resizing PID ${pid} to ${cols}x${rows}`);
    terminals[pid].resize(cols, rows);
  }
});

// Session Logging
const logStreams = {};
ipcMain.on('toggle-logging', (event, { pid, sessionId, label, enabled, rotationLimitMB }) => {
  if (enabled) {
    const logsDir = path.join(app.getPath('userData'), 'logs');
    if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

    // Perform rotation before starting a new log
    if (rotationLimitMB) {
      rotateLogs(rotationLimitMB);
    }

    const now = new Date();
    const dateStr = `${String(now.getDate()).padStart(2, '0')}-${String(now.getMonth() + 1).padStart(2, '0')}-${now.getFullYear()}`;
    const timeStr = `${String(now.getHours()).padStart(2, '0')}h${String(now.getMinutes()).padStart(2, '0')}`;
    const safeLabel = (label || 'session').replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const logPath = path.join(logsDir, `${safeLabel}_${dateStr}_${timeStr}.log`);

    logStreams[pid] = fs.createWriteStream(logPath, { flags: 'a' });
    console.log(`[Log] Started logging for PID ${pid} to ${logPath}`);
  } else {
    if (logStreams[pid]) {
      logStreams[pid].end();
      delete logStreams[pid];
      console.log(`[Log] Stopped logging for PID ${pid}`);
    }
  }
});

function rotateLogs(limitMB) {
  const logsDir = path.join(app.getPath('userData'), 'logs');
  if (!fs.existsSync(logsDir)) return;

  try {
    const files = fs.readdirSync(logsDir)
      .filter(f => f.endsWith('.log'))
      .map(f => {
        const fullPath = path.join(logsDir, f);
        const stats = fs.statSync(fullPath);
        return { name: f, path: fullPath, size: stats.size, mtime: stats.mtime };
      })
      .sort((a, b) => a.mtime - b.mtime); // Oldest first

    let totalSize = files.reduce((acc, f) => acc + f.size, 0);
    const limitBytes = limitMB * 1024 * 1024;

    while (totalSize > limitBytes && files.length > 0) {
      const oldest = files.shift();
      fs.unlinkSync(oldest.path);
      totalSize -= oldest.size;
      console.log(`[Log Rotation] Deleted oldest log: ${oldest.name} (Size: ${oldest.size} bytes)`);
    }
  } catch (e) {
    console.error('Failed to rotate logs', e);
  }
}

ipcMain.handle('list-logs', async () => {
  const logsDir = path.join(app.getPath('userData'), 'logs');
  if (!fs.existsSync(logsDir)) return [];
  try {
    const files = fs.readdirSync(logsDir);
    return files.filter(f => f.endsWith('.log')).map(f => {
      const stats = fs.statSync(path.join(logsDir, f));
      return {
        name: f,
        size: stats.size,
        mtime: stats.mtime
      };
    });
  } catch (e) {
    console.error('Failed to list logs', e);
    return [];
  }
});

ipcMain.handle('read-log', async (event, filename) => {
  if (typeof filename !== 'string') return null;

  // Strict validation: Allow only alphanumeric, underscores, dashes, and .log extension
  if (!/^[a-zA-Z0-9_\-]+\.log$/.test(filename)) {
    console.error('Security: Invalid log filename requested:', filename);
    return null;
  }

  const logPath = path.join(app.getPath('userData'), 'logs', filename);

  // Double check that the resolved path is inside the logs directory
  const logsDir = path.join(app.getPath('userData'), 'logs');
  if (!logPath.startsWith(logsDir)) {
    console.error('Security: Path traversal attempt detected:', filename);
    return null;
  }

  try {
    return fs.readFileSync(logPath, 'utf8');
  } catch (e) {
    console.error('Failed to read log');
    return null;
  }
});

ipcMain.handle('delete-logs', async (event, filenames) => {
  try {
    filenames.forEach(filename => {
      if (typeof filename !== 'string') return;

      // Strict validation
      if (!/^[a-zA-Z0-9_\-]+\.log$/.test(filename)) {
        console.error('Security: Invalid log filename for deletion:', filename);
        return;
      }

      const logPath = path.join(app.getPath('userData'), 'logs', filename);
      const logsDir = path.join(app.getPath('userData'), 'logs');

      if (logPath.startsWith(logsDir) && fs.existsSync(logPath)) {
        fs.unlinkSync(logPath);
      }
    });
    return true;
  } catch (e) {
    console.error('Failed to delete logs');
    return false;
  }
});

ipcMain.handle('download-log', async (event, filename) => {
  if (typeof filename !== 'string') return false;
  const { dialog } = require('electron');
  const safeFilename = path.basename(filename);
  const logPath = path.join(app.getPath('userData'), 'logs', safeFilename);


  if (!fs.existsSync(logPath)) return false;

  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Download Log File',
    defaultPath: filename,
    filters: [{ name: 'Log Files', extensions: ['log'] }, { name: 'Text Files', extensions: ['txt'] }]
  });

  if (filePath) {
    try {
      fs.copyFileSync(logPath, filePath);
      return true;
    } catch (e) {
      console.error('Failed to download log', e);
      return false;
    }
  }
  return false;
});

// Export connections
// Export connections
ipcMain.handle('export-connections', async (event, connections, password) => {
  const { dialog } = require('electron');
  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Connections (Encrypted)',
    defaultPath: 'owl_connections_backup.json',
    filters: [{ name: 'JSON', extensions: ['json'] }]
  });
  if (filePath) {
    try {
      if (!password) {
        console.error('Export requires a password');
        return false;
      }

      // Generate NEW salt for this export
      const salt = crypto.randomBytes(SALT_LENGTH);
      const key = deriveKey(password, salt);

      const encrypted = encrypt(JSON.stringify(connections), key);

      const exportData = {
        version: 1,
        salt: salt.toString('hex'),
        iv: encrypted.iv,
        tag: encrypted.tag,
        content: encrypted.content,
        isExport: true
      };

      fs.writeFileSync(filePath, JSON.stringify(exportData, null, 2));
      return true;
    } catch (e) {
      console.error('Failed to export connections', e);
      return false;
    }
  }
  return false;
});

// Import connections
ipcMain.handle('import-connections', async () => {
  const { dialog } = require('electron');
  const { filePaths } = await dialog.showOpenDialog(mainWindow, {
    title: 'Import Connections',
    filters: [{ name: 'JSON', extensions: ['json'] }],
    properties: ['openFile']
  });
  if (filePaths && filePaths.length > 0) {
    try {
      const raw = fs.readFileSync(filePaths[0], 'utf8');
      const data = JSON.parse(raw);

      // Handle Encrypted Import
      if (data.salt && data.content) {
        // Check if we can decrypt with current vault key (Same Vault)
        if (vaultKey && vaultSalt && data.salt === vaultSalt.toString('hex')) {
          try {
            const decrypted = decrypt(data, vaultKey);
            return JSON.parse(decrypted);
          } catch (e) {
            // Should not happen if salts match, but just in case
          }
        }

        // Different salt or locked vault -> Need password
        return { status: 'needs_password', filePath: filePaths[0] };
      }

      return data;
    } catch (e) {
      console.error('Failed to import connections', e);
      return null;
    }
  }
  return null;
});

ipcMain.handle('decrypt-import-file', async (event, filePath, password) => {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);

    if (!data.salt || !data.content) return null;

    const salt = Buffer.from(data.salt, 'hex');
    const key = deriveKey(password, salt);

    const decrypted = decrypt(data, key);
    return JSON.parse(decrypted);
  } catch (e) {
    console.error('Failed to decrypt import file', e);
    return null;
  }
});

ipcMain.handle('open-file-dialog', async (event, options) => {
  const allowedExtensions = ['key', 'pem', 'id_rsa', 'id_ed25519', 'json'];
  const { dialog } = require('electron');

  const { filePaths } = await dialog.showOpenDialog(mainWindow, {
    title: options.title || 'Open File',
    filters: [
      { name: 'Allowed Files', extensions: allowedExtensions }
    ],
    properties: ['openFile']
  });

  if (filePaths && filePaths.length > 0) {
    const filePath = filePaths[0];
    const ext = path.extname(filePath).slice(1);

    // Validate extension (allow no extension for some keys like id_rsa)
    if (ext && !allowedExtensions.includes(ext)) {
      console.error('Security: Invalid file type selected');
      return null;
    }
    return filePath;
  }
  return null;
});
// SFTP Handling with Connection Pooling

async function getSftpConnection(connection) {
  const session = await getRawConnection(connection);
  if (session.sftp) return session.sftp;

  return new Promise((resolve, reject) => {
    session.conn.sftp((err, sftp) => {
      if (err) return reject(err);
      session.sftp = sftp;
      resolve(sftp);
    });
  });
}


ipcMain.handle('sftp-list', async (event, { connection, path: remotePath }) => {
  try {
    const sftp = await getSftpConnection(connection);

    // If no path, get the real path of '.' (home directory)
    const targetPath = remotePath || await new Promise((resolve, reject) => {
      sftp.realpath('.', (err, absPath) => {
        if (err) resolve('.'); // Fallback to '.'
        else resolve(absPath);
      });
    });

    return new Promise((resolve, reject) => {
      sftp.readdir(targetPath, (err, list) => {
        if (err) return reject(err);
        const formatted = list.map(item => ({
          name: item.filename,
          type: item.longname.startsWith('d') ? 'directory' : 'file',
          size: item.attrs.size,
          mtime: item.attrs.mtime,
          permissions: item.attrs.permissions
        }));
        resolve(formatted);
      });
    });
  } catch (err) {
    console.error('SFTP List Error:', err);
    throw err;
  }
});

ipcMain.handle('sftp-download', async (event, { connection, remotePath }) => {
  const { dialog } = require('electron');
  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Download File',
    defaultPath: path.basename(remotePath)
  });

  if (!filePath) return false;

  try {
    const sftp = await getSftpConnection(connection);
    return new Promise((resolve, reject) => {
      sftp.fastGet(remotePath, filePath, (err) => {
        if (err) reject(err);
        else resolve(true);
      });
    });
  } catch (err) {
    console.error('SFTP Download Error:', err);
    throw err;
  }
});

ipcMain.handle('sftp-upload', async (event, { connection, remoteDir }) => {
  try {
    const { dialog } = require('electron');
    const { filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: 'Upload File',
      properties: ['openFile']
    });

    if (!filePaths || filePaths.length === 0) {
      console.log('[SFTP Upload] User cancelled file selection');
      return false;
    }

    const localPath = filePaths[0];
    // Fix: Use forward slash for remote paths regardless of local OS
    const filename = path.basename(localPath);
    const remotePath = remoteDir.endsWith('/') ? remoteDir + filename : remoteDir + '/' + filename;

    console.log(`[SFTP Upload] Uploading ${localPath} to ${remotePath}`);

    const sftp = await getSftpConnection(connection);

    return new Promise((resolve, reject) => {
      sftp.fastPut(localPath, remotePath, (err) => {
        if (err) {
          console.error('[SFTP Upload] Error:', err.message);
          reject(new Error(`Upload failed: ${err.message}`));
        } else {
          console.log('[SFTP Upload] Success');
          resolve(true);
        }
      });
    });
  } catch (err) {
    console.error('[SFTP Upload] Exception:', err.message);
    throw new Error(`Upload failed: ${err.message}`);
  }
});

// Resource Metrics Handling
ipcMain.handle('get-metrics', async (event, { connection }) => {
  try {
    const cmd = `
      cpu=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | awk '{print 100 - $1}');
      ram=$(free | grep Mem | awk '{print $3/$2 * 100.0}');
      disk=$(df / --output=pcent | tail -1 | tr -dc '0-9');
      uptime=$(uptime -p | sed 's/up //');
      os=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2);
      echo "$cpu|$ram|$disk|$uptime|$os"
    `;

    let data;
    if (connection && connection.id === 'local-terminal') {
      const { exec } = require('child_process');
      data = await new Promise((resolve, reject) => {
        exec(cmd, (error, stdout, stderr) => {
          if (error) reject(error);
          else resolve(stdout);
        });
      });
    } else {
      const result = await execQueued(connection, cmd);
      data = result.data;
    }

    const parts = data.trim().split('|');
    if (parts.length >= 5) {
      return {
        cpu: parseFloat(parts[0]) || 0,
        ram: parseFloat(parts[1]) || 0,
        disk: parseFloat(parts[2]) || 0,
        uptime: parts[3] || 'Unknown',
        os: parts[4] || 'Unknown'
      };
    }
    return null;
  } catch (err) {
    console.error('Metrics Error:', err);
    return null;
  }
});

ipcMain.handle('get-dir-size', async (event, { connection, path }) => {
  try {
    const cmd = `du -sh ${escapeShellArg(path)} 2>/dev/null | cut -f1`;

    let data;
    if (connection && connection.id === 'local-terminal') {
      const { exec } = require('child_process');
      data = await new Promise((resolve, reject) => {
        exec(cmd, (error, stdout, stderr) => {
          if (error) reject(error);
          else resolve(stdout);
        });
      });
    } else {
      const result = await execQueued(connection, cmd);
      data = result.data;
    }

    return data.trim() || '0';
  } catch (err) {
    return 'N/A';
  }
});

// Process Management
ipcMain.handle('get-processes', async (event, { connection }) => {
  try {
    const cmd = `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -n 20 | tail -n +2`;

    let data;
    if (connection && connection.id === 'local-terminal') {
      const { exec } = require('child_process');
      data = await new Promise((resolve, reject) => {
        exec(cmd, (error, stdout, stderr) => {
          if (error) reject(error);
          else resolve(stdout);
        });
      });
    } else {
      const result = await execQueued(connection, cmd);
      data = result.data;
    }

    return data.trim().split('\n').map(line => {
      const [pid, user, cpu, mem, ...comm] = line.trim().split(/\s+/);
      return { pid, user, cpu, mem, comm: comm.join(' ') };
    });
  } catch (err) {
    console.error('Get Processes Error:', err);
    return [];
  }
});

ipcMain.handle('kill-process', async (event, { connection, pid }) => {
  try {
    const safePid = parseInt(pid);
    if (isNaN(safePid)) return false;
    await execQueued(connection, `kill -9 ${safePid}`);

    return true;
  } catch (err) {
    console.error('Kill Process Error:', err);
    return false;
  }
});



// Protocol Launcher
ipcMain.handle('launch-protocol', async (event, connection) => {
  const { shell } = require('electron');
  const protocol = connection.protocol;
  const host = connection.host;
  const port = connection.port;
  const user = connection.user;
  const password = connection.password;

  try {
    if (protocol === 'rdp') {
      const safeUser = user ? escapeShellArg(user).replace(/'/g, '') : '';
      const safeHost = host.replace(/[^a-zA-Z0-9.-]/g, '');
      const safePort = port ? parseInt(port) : '';

      const url = `rdp://${safeUser ? safeUser + '@' : ''}${safeHost}${safePort ? ':' + safePort : ''}`;
      console.log('Launching RDP:', url);
      await shell.openExternal(url);
      return true;
    } else if (protocol === 'vnc') {
      const safeUser = user ? escapeShellArg(user).replace(/'/g, '') : '';
      const safeHost = host.replace(/[^a-zA-Z0-9.-]/g, '');
      const safePort = port ? parseInt(port) : '';

      const url = `vnc://${safeUser ? safeUser + '@' : ''}${safeHost}${safePort ? ':' + safePort : ''}`;
      console.log('Launching VNC:', url);
      await shell.openExternal(url);
      return true;
    }

  } catch (err) {
    console.error('Failed to launch protocol:', err);
    return false;
  }
});

// Snippets Handling
ipcMain.handle('load-snippets', async () => {
  const snippetsPath = path.join(app.getPath('userData'), 'snippets.json');
  if (!fs.existsSync(snippetsPath)) return [];
  try {
    const data = fs.readFileSync(snippetsPath, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    console.error('Failed to load snippets', e);
    return [];
  }
});

ipcMain.handle('save-snippets', async (event, snippets) => {
  const snippetsPath = path.join(app.getPath('userData'), 'snippets.json');
  try {
    fs.writeFileSync(snippetsPath, JSON.stringify(snippets, null, 2));
    return true;
  } catch (e) {
    console.error('Failed to save snippets', e);
    return false;
  }
});
