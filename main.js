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
const https = require('https');
const http = require('http');
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
const sageStreams = new Map();

function isSafeSshOptionKey(key) {
  return /^[A-Za-z][A-Za-z0-9]*$/.test(key);
}

function isSafeSshOptionValue(value) {
  return typeof value === 'string' && value.length > 0 && value.length < 256 && !/[\r\n\0]/.test(value);
}

function getEnabledSshOptions(connection) {
  const map = {};
  if (!Array.isArray(connection?.sshOptions)) return map;
  for (const opt of connection.sshOptions) {
    if (!opt || !opt.enabled) continue;
    const key = String(opt.key || '').trim();
    const value = String(opt.value ?? '').trim();
    if (!isSafeSshOptionKey(key) || !isSafeSshOptionValue(value)) continue;
    map[key] = value;
  }
  return map;
}

function buildSshConnectOptions(connection, sock = undefined) {
  const enabled = getEnabledSshOptions(connection);
  const connectTimeout = parseInt(enabled.ConnectTimeout, 10);
  const aliveInterval = parseInt(enabled.ServerAliveInterval, 10);
  const aliveCount = parseInt(enabled.ServerAliveCountMax, 10);
  const compression = String(enabled.Compression || '').toLowerCase();

  const opts = {
    host: connection.host,
    port: connection.port || 22,
    username: connection.user,
    password: connection.authType === 'key' ? undefined : connection.password,
    privateKey: (connection.authType === 'key' && connection.keyPath && fs.existsSync(connection.keyPath)) ? fs.readFileSync(connection.keyPath) : undefined,
    passphrase: connection.authType === 'key' ? connection.passphrase : undefined,
    readyTimeout: Number.isFinite(connectTimeout) && connectTimeout > 0 ? connectTimeout * 1000 : 30000,
    keepaliveInterval: Number.isFinite(aliveInterval) && aliveInterval > 0 ? aliveInterval * 1000 : 10000,
    keepaliveCountMax: Number.isFinite(aliveCount) && aliveCount > 0 ? aliveCount : 3,
    sock
  };

  if (compression === 'yes' || compression === 'true' || compression === 'zlib') {
    opts.compress = true;
  }

  return opts;
}

function appendSshCliOptions(spawnArgs, connection) {
  if (!Array.isArray(connection?.sshOptions)) return;
  for (const opt of connection.sshOptions) {
    if (!opt || !opt.enabled) continue;
    const key = String(opt.key || '').trim();
    const value = String(opt.value ?? '').trim();
    if (!isSafeSshOptionKey(key) || !isSafeSshOptionValue(value)) continue;
    spawnArgs.push('-o', `${key}=${value}`);
  }
}

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
      }).connect(buildSshConnectOptions(connection, sock));
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

app.on('before-quit', async () => {
  for (const streamId of [...sageStreams.keys()]) {
    stopSageStream(streamId);
  }
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
  const sageConfigPath = path.join(app.getPath('userData'), 'sage-config.json');

  for (const filePath of [connectionsPath, sageConfigPath]) {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  for (const streamId of [...sageStreams.keys()]) {
    stopSageStream(streamId);
  }

  vaultKey = null;
  vaultSalt = null;
  return true;
});

ipcMain.handle('lock-vault', async () => {
  for (const [, req] of sageStreams) {
    try { req.destroy(); } catch (_) { /* ignore */ }
  }
  sageStreams.clear();
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

    // Advanced OpenSSH options (-o Key=Value)
    appendSshCliOptions(spawnArgs, connection);

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

// Docker Explorer
const dockerLogStreams = new Map();

function sanitizeDockerRef(ref) {
  if (!ref || typeof ref !== 'string') return null;
  const trimmed = ref.trim();
  if (/^[a-f0-9]{12,64}$/i.test(trimmed)) return trimmed;
  if (/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(trimmed)) return trimmed;
  return null;
}

function sanitizeVolumeName(name) {
  if (!name || typeof name !== 'string') return null;
  const trimmed = name.trim();
  if (/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,255}$/.test(trimmed)) return trimmed;
  return null;
}

function sanitizeImageRef(repository, tag, id) {
  if (id && /^[a-f0-9]{12,64}$/i.test(id)) return id;
  if (repository && tag) {
    const ref = tag === '<none>' ? repository : `${repository}:${tag}`;
    if (/^[a-zA-Z0-9@][a-zA-Z0-9@._\/:-]{0,255}$/.test(ref)) return ref;
  }
  return sanitizeDockerRef(repository);
}

async function execRemoteOrLocal(connection, cmd, timeout = 30000) {
  if (connection && connection.id === 'local-terminal') {
    const { exec } = require('child_process');
    return new Promise((resolve, reject) => {
      exec(cmd, { timeout, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve({ code: 0, data: stdout, stderr: stderr || '' });
        }
      });
    });
  }
  return execQueued(connection, cmd, { timeout });
}

function parseDockerLines(data) {
  return data
    .trim()
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
}

function stopDockerLogStream(streamId) {
  const entry = dockerLogStreams.get(streamId);
  if (!entry) return;
  if (entry.type === 'local') {
    try { entry.proc.kill('SIGTERM'); } catch (e) { /* ignore */ }
  } else if (entry.stream) {
    try { entry.stream.close(); } catch (e) { /* ignore */ }
  }
  dockerLogStreams.delete(streamId);
}

ipcMain.handle('docker-check', async (event, { connection }) => {
  try {
    const cmd = 'command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo "ok"';
    const result = await execRemoteOrLocal(connection, cmd);
    return result.data.trim() === 'ok';
  } catch (err) {
    console.error('Docker Check Error:', err.message);
    return false;
  }
});

ipcMain.handle('docker-get-stats', async (event, { connection }) => {
  try {
    const cmd = 'RUNNING=$(docker ps -q 2>/dev/null | wc -l); TOTAL=$(docker ps -aq 2>/dev/null | wc -l); IMAGES=$(docker images -q 2>/dev/null | wc -l); VOLUMES=$(docker volume ls -q 2>/dev/null | wc -l); echo "$RUNNING|$TOTAL|$IMAGES|$VOLUMES"';
    const result = await execRemoteOrLocal(connection, cmd);
    const [running, total, images, volumes] = result.data.trim().split('|');
    return {
      running: parseInt(running, 10) || 0,
      total: parseInt(total, 10) || 0,
      images: parseInt(images, 10) || 0,
      volumes: parseInt(volumes, 10) || 0
    };
  } catch (err) {
    console.error('Docker Stats Error:', err.message);
    return { running: 0, total: 0, images: 0, volumes: 0 };
  }
});

ipcMain.handle('docker-list-containers', async (event, { connection }) => {
  try {
    const cmd = `docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}|{{.State}}|{{.RunningFor}}|{{.Size}}' 2>/dev/null`;
    const result = await execRemoteOrLocal(connection, cmd);
    return parseDockerLines(result.data).map(line => {
      const [id, name, image, status, ports, state, runningFor, size] = line.split('|');
      return {
        id, name, image, status,
        ports: ports || '',
        state: state || '',
        runningFor: runningFor || '',
        size: size || ''
      };
    });
  } catch (err) {
    console.error('Docker List Containers Error:', err.message);
    throw err;
  }
});

ipcMain.handle('docker-list-images', async (event, { connection }) => {
  try {
    const cmd = `docker images --format '{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedSince}}' 2>/dev/null`;
    const result = await execRemoteOrLocal(connection, cmd);
    return parseDockerLines(result.data).map(line => {
      const [id, repository, tag, size, created] = line.split('|');
      return { id, repository, tag, size, created };
    });
  } catch (err) {
    console.error('Docker List Images Error:', err.message);
    throw err;
  }
});

ipcMain.handle('docker-list-volumes', async (event, { connection }) => {
  try {
    const cmd = `docker volume ls --format '{{.Name}}|{{.Driver}}' 2>/dev/null`;
    const result = await execRemoteOrLocal(connection, cmd);
    return parseDockerLines(result.data).map(line => {
      const [name, driver] = line.split('|');
      return { name, driver: driver || 'local' };
    });
  } catch (err) {
    console.error('Docker List Volumes Error:', err.message);
    throw err;
  }
});

ipcMain.handle('docker-container-action', async (event, { connection, containerRef, action }) => {
  const ref = sanitizeDockerRef(containerRef);
  if (!ref) return { success: false, error: 'Invalid container reference' };

  const allowed = ['start', 'stop', 'restart', 'rm', 'kill', 'pause', 'unpause'];
  if (!allowed.includes(action)) return { success: false, error: 'Invalid action' };

  try {
    const cmd = action === 'rm'
      ? `docker rm -f ${escapeShellArg(ref)}`
      : `docker ${action} ${escapeShellArg(ref)}`;
    await execRemoteOrLocal(connection, cmd);
    return { success: true };
  } catch (err) {
    console.error('Docker Container Action Error:', err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('docker-image-action', async (event, { connection, imageRef, action }) => {
  const ref = sanitizeDockerRef(imageRef) || (typeof imageRef === 'string' ? imageRef : null);
  if (!ref || !/^[a-zA-Z0-9@][a-zA-Z0-9@._\/:-]{0,255}$/.test(ref)) {
    return { success: false, error: 'Invalid image reference' };
  }

  if (action !== 'rm') return { success: false, error: 'Invalid action' };

  try {
    await execRemoteOrLocal(connection, `docker rmi -f ${escapeShellArg(ref)}`);
    return { success: true };
  } catch (err) {
    console.error('Docker Image Action Error:', err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('docker-volume-action', async (event, { connection, volumeName, action }) => {
  const name = sanitizeVolumeName(volumeName);
  if (!name) return { success: false, error: 'Invalid volume name' };

  if (action !== 'rm') return { success: false, error: 'Invalid action' };

  try {
    await execRemoteOrLocal(connection, `docker volume rm -f ${escapeShellArg(name)}`);
    return { success: true };
  } catch (err) {
    console.error('Docker Volume Action Error:', err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('docker-inspect', async (event, { connection, resourceType, resourceRef }) => {
  let ref = null;
  if (resourceType === 'volume') {
    ref = sanitizeVolumeName(resourceRef);
  } else {
    ref = sanitizeDockerRef(resourceRef);
  }
  if (!ref) return { success: false, error: 'Invalid resource reference' };

  const allowed = ['container', 'image', 'volume'];
  if (!allowed.includes(resourceType)) return { success: false, error: 'Invalid resource type' };

  try {
    const cmd = `docker inspect ${escapeShellArg(ref)} 2>/dev/null`;
    const result = await execRemoteOrLocal(connection, cmd, 45000);
    const parsed = JSON.parse(result.data.trim());
    return { success: true, data: parsed[0] || parsed };
  } catch (err) {
    console.error('Docker Inspect Error:', err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('docker-logs-stream-start', async (event, { connection, containerRef, tail = 200 }) => {
  const ref = sanitizeDockerRef(containerRef);
  if (!ref) return { success: false, error: 'Invalid container reference' };

  const streamId = require('crypto').randomBytes(8).toString('hex');
  const safeTail = Math.min(Math.max(parseInt(tail, 10) || 200, 10), 1000);
  const sender = event.sender;

  const pushChunk = (chunk) => {
    if (!sender.isDestroyed()) {
      sender.send('docker-logs-stream-data', { streamId, chunk: chunk.toString() });
    }
  };

  const pushEnd = () => {
    dockerLogStreams.delete(streamId);
    if (!sender.isDestroyed()) {
      sender.send('docker-logs-stream-end', { streamId });
    }
  };

  try {
    if (connection && connection.id === 'local-terminal') {
      const { spawn } = require('child_process');
      const proc = spawn('docker', ['logs', '-f', '--tail', String(safeTail), ref], {
        stdio: ['ignore', 'pipe', 'pipe']
      });
      proc.stdout.on('data', pushChunk);
      proc.stderr.on('data', pushChunk);
      proc.on('close', pushEnd);
      proc.on('error', pushEnd);
      dockerLogStreams.set(streamId, { type: 'local', proc });
    } else {
      const session = await getRawConnection(connection);
      const cmd = `docker logs -f --tail ${safeTail} ${escapeShellArg(ref)} 2>&1`;
      await new Promise((resolve, reject) => {
        session.conn.exec(cmd, (err, stream) => {
          if (err) return reject(err);
          stream.on('data', pushChunk);
          if (stream.stderr) stream.stderr.on('data', pushChunk);
          stream.on('close', pushEnd);
          stream.on('error', pushEnd);
          dockerLogStreams.set(streamId, { type: 'ssh', stream });
          resolve();
        });
      });
    }
    return { success: true, streamId };
  } catch (err) {
    stopDockerLogStream(streamId);
    console.error('Docker Log Stream Start Error:', err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('docker-logs-stream-stop', async (event, { streamId }) => {
  if (streamId) stopDockerLogStream(streamId);
  return { success: true };
});

ipcMain.handle('docker-logs-stream-stop-all', async () => {
  for (const streamId of [...dockerLogStreams.keys()]) {
    stopDockerLogStream(streamId);
  }
  return { success: true };
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


// --- OWL Sage ---

const SAGE_PROVIDER_DEFAULTS = {
  litellm: {
    baseUrl: 'http://localhost:4000/v1',
    model: 'gpt-4o-mini',
    requiresBaseUrl: true,
    apiStyle: 'openai'
  },
  openai: {
    baseUrl: 'https://api.openai.com/v1',
    model: 'gpt-4o-mini',
    requiresBaseUrl: false,
    apiStyle: 'openai'
  },
  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    model: 'claude-sonnet-4-20250514',
    requiresBaseUrl: false,
    apiStyle: 'anthropic'
  },
  gemini: {
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
    model: 'gemini-2.0-flash',
    requiresBaseUrl: false,
    apiStyle: 'openai'
  }
};

function getSageConfigPath() {
  return path.join(app.getPath('userData'), 'sage-config.json');
}

function defaultSageConfig() {
  return {
    enabled: false,
    provider: 'litellm',
    baseUrl: SAGE_PROVIDER_DEFAULTS.litellm.baseUrl,
    apiKey: '',
    model: SAGE_PROVIDER_DEFAULTS.litellm.model,
    redaction: true
  };
}

function normalizeSageProvider(provider) {
  return SAGE_PROVIDER_DEFAULTS[provider] ? provider : 'litellm';
}

function getSageProviderMeta(provider) {
  return SAGE_PROVIDER_DEFAULTS[normalizeSageProvider(provider)];
}

function resolveSageEndpoint(config) {
  const provider = normalizeSageProvider(config.provider);
  const meta = getSageProviderMeta(provider);
  const configured = (config.baseUrl || '').trim();
  const baseUrl = configured || meta.baseUrl;
  return { provider, meta, baseUrl };
}

function isSageConfigReady(config) {
  if (!config || !config.enabled || !config.apiKey) return false;
  const { provider, meta, baseUrl } = resolveSageEndpoint(config);
  if (meta.requiresBaseUrl && !baseUrl) return false;
  if (!baseUrl && provider !== 'anthropic') return false;
  return true;
}

function readSageConfig() {
  if (!vaultKey) return null;
  const configPath = getSageConfigPath();
  if (!fs.existsSync(configPath)) return defaultSageConfig();
  try {
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    let parsed;
    if (raw.iv && raw.content) {
      const decrypted = decrypt(raw, vaultKey);
      parsed = JSON.parse(decrypted);
    } else {
      parsed = raw;
    }
    const merged = { ...defaultSageConfig(), ...parsed };
    merged.provider = normalizeSageProvider(merged.provider);
    return merged;
  } catch (e) {
    console.error('[Sage] Failed to read config:', e.message);
    return defaultSageConfig();
  }
}

function writeSageConfig(config) {
  if (!vaultKey) throw new Error('Vault is locked');
  const encrypted = encrypt(JSON.stringify(config), vaultKey);
  fs.writeFileSync(getSageConfigPath(), JSON.stringify(encrypted, null, 2));
}

function redactSecrets(text) {
  if (!text || typeof text !== 'string') return text;
  let redacted = text;
  redacted = redacted.replace(/-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');
  redacted = redacted.replace(/(?:password|passwd|pwd|secret|api[_-]?key|token|authorization)\s*[=:]\s*\S+/gi, '[REDACTED_CREDENTIAL]');
  redacted = redacted.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED_JWT]');
  redacted = redacted.replace(/\bsk-[A-Za-z0-9]{10,}\b/g, '[REDACTED_API_KEY]');
  return redacted;
}

function normalizeSageBaseUrl(baseUrl, apiStyle) {
  const trimmed = (baseUrl || '').trim().replace(/\/+$/, '');
  if (!trimmed) return '';
  if (apiStyle === 'anthropic') {
    return trimmed.replace(/\/v1$/, '');
  }
  return trimmed.endsWith('/v1') || trimmed.includes('/openai') ? trimmed : `${trimmed}/v1`;
}

function stopSageStream(streamId) {
  const req = sageStreams.get(streamId);
  if (req) {
    try { req.destroy(); } catch (_) { /* ignore */ }
    sageStreams.delete(streamId);
  }
}

function sendSageHttpRequest(webContents, streamId, endpoint, headers, body, onDataLine) {
  const isHttps = endpoint.protocol === 'https:';
  const lib = isHttps ? https : http;
  const port = endpoint.port || (isHttps ? 443 : 80);
  const payload = typeof body === 'string' ? body : JSON.stringify(body);

  const options = {
    hostname: endpoint.hostname,
    port,
    path: `${endpoint.pathname}${endpoint.search}`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      ...headers
    }
  };

  const req = lib.request(options, (res) => {
    if (res.statusCode < 200 || res.statusCode >= 300) {
      let errorBody = '';
      res.on('data', (chunk) => { errorBody += chunk.toString(); });
      res.on('end', () => {
        let message = `Sage request failed (${res.statusCode})`;
        try {
          const parsed = JSON.parse(errorBody);
          message = parsed.error?.message || parsed.message || parsed.error || message;
        } catch (_) {
          if (errorBody) message = errorBody.slice(0, 300);
        }
        webContents.send('sage-stream-error', { streamId, error: message });
        sageStreams.delete(streamId);
      });
      return;
    }

    let buffer = '';
    res.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        onDataLine(line);
      }
    });

    res.on('end', () => {
      if (sageStreams.has(streamId)) {
        webContents.send('sage-stream-end', { streamId });
        sageStreams.delete(streamId);
      }
    });
  });

  req.on('error', (err) => {
    webContents.send('sage-stream-error', { streamId, error: err.message });
    sageStreams.delete(streamId);
  });

  sageStreams.set(streamId, req);
  req.write(payload);
  req.end();
}

function streamOpenAICompatibleChat(webContents, streamId, config, messages, baseUrl) {
  const base = normalizeSageBaseUrl(baseUrl, 'openai');
  if (!base) {
    webContents.send('sage-stream-error', { streamId, error: 'Provider base URL is not configured.' });
    return;
  }

  let endpoint;
  try {
    endpoint = new URL(`${base}/chat/completions`);
  } catch (err) {
    webContents.send('sage-stream-error', { streamId, error: 'Invalid provider base URL.' });
    return;
  }

  const body = {
    model: config.model || getSageProviderMeta(config.provider).model,
    messages,
    stream: true,
    temperature: 0.3
  };

  sendSageHttpRequest(
    webContents,
    streamId,
    endpoint,
    { Authorization: `Bearer ${config.apiKey}` },
    body,
    (line) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) return;
      const data = trimmed.slice(5).trim();
      if (data === '[DONE]') {
        webContents.send('sage-stream-end', { streamId });
        sageStreams.delete(streamId);
        return;
      }
      try {
        const parsed = JSON.parse(data);
        const content = parsed.choices?.[0]?.delta?.content;
        if (content) {
          webContents.send('sage-stream-chunk', { streamId, chunk: content });
        }
      } catch (_) { /* ignore malformed chunks */ }
    }
  );
}

function streamAnthropicChat(webContents, streamId, config, messages, baseUrl) {
  const base = normalizeSageBaseUrl(baseUrl || SAGE_PROVIDER_DEFAULTS.anthropic.baseUrl, 'anthropic');
  let endpoint;
  try {
    endpoint = new URL(`${base}/v1/messages`);
  } catch (err) {
    webContents.send('sage-stream-error', { streamId, error: 'Invalid Anthropic base URL.' });
    return;
  }

  let system = '';
  const apiMessages = [];
  for (const msg of messages) {
    if (msg.role === 'system') {
      system = system ? `${system}\n\n${msg.content}` : msg.content;
      continue;
    }
    if (msg.role === 'user' || msg.role === 'assistant') {
      apiMessages.push({ role: msg.role, content: msg.content });
    }
  }

  const body = {
    model: config.model || SAGE_PROVIDER_DEFAULTS.anthropic.model,
    max_tokens: 4096,
    temperature: 0.3,
    stream: true,
    messages: apiMessages
  };
  if (system) body.system = system;

  sendSageHttpRequest(
    webContents,
    streamId,
    endpoint,
    {
      'x-api-key': config.apiKey,
      'anthropic-version': '2023-06-01'
    },
    body,
    (line) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) return;
      const data = trimmed.slice(5).trim();
      if (!data || data === '[DONE]') {
        if (data === '[DONE]') {
          webContents.send('sage-stream-end', { streamId });
          sageStreams.delete(streamId);
        }
        return;
      }
      try {
        const parsed = JSON.parse(data);
        if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
          webContents.send('sage-stream-chunk', { streamId, chunk: parsed.delta.text });
        } else if (parsed.type === 'message_stop') {
          webContents.send('sage-stream-end', { streamId });
          sageStreams.delete(streamId);
        } else if (parsed.type === 'error') {
          webContents.send('sage-stream-error', {
            streamId,
            error: parsed.error?.message || 'Anthropic stream error'
          });
          sageStreams.delete(streamId);
        }
      } catch (_) { /* ignore malformed chunks */ }
    }
  );
}

function streamSageChat(webContents, streamId, config, messages) {
  if (!config.apiKey) {
    webContents.send('sage-stream-error', { streamId, error: 'API key is not configured.' });
    return;
  }

  const { meta, baseUrl } = resolveSageEndpoint(config);
  if (meta.apiStyle === 'anthropic') {
    streamAnthropicChat(webContents, streamId, config, messages, baseUrl);
    return;
  }

  streamOpenAICompatibleChat(webContents, streamId, config, messages, baseUrl);
}

ipcMain.handle('load-sage-config', async () => {
  if (!vaultKey) return null;
  return readSageConfig();
});

ipcMain.handle('save-sage-config', async (event, config) => {
  try {
    const provider = normalizeSageProvider(config?.provider);
    const meta = getSageProviderMeta(provider);
    writeSageConfig({
      ...defaultSageConfig(),
      ...config,
      provider,
      baseUrl: (config?.baseUrl || '').trim() || (meta.requiresBaseUrl ? meta.baseUrl : ''),
      model: (config?.model || '').trim() || meta.model
    });
    return true;
  } catch (e) {
    console.error('[Sage] Failed to save config:', e.message);
    return false;
  }
});

ipcMain.handle('sage-chat-stream-start', async (event, { messages, context }) => {
  const config = readSageConfig();
  if (!config || !config.enabled) {
    return { success: false, error: 'OWL Sage is not enabled. Configure it in Settings.' };
  }
  if (!isSageConfigReady(config)) {
    return { success: false, error: 'Sage provider, API key, and required fields must be configured.' };
  }

  const streamId = `sage-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const systemPrompt = `You are OWL Sage, an expert Linux and DevOps assistant embedded in OWL Connection Manager.
Help users diagnose server issues, explain errors, and suggest shell commands.
Rules:
- Be concise and actionable
- When suggesting commands, wrap each in a markdown code block with language bash
- Warn before destructive commands (rm -rf, kill -9, drop database, etc.)
- Only use facts from the provided context; do not invent metrics or logs
- If context is insufficient, say what additional info to gather`;

  let contextBlock = context || '';
  if (config.redaction) {
    contextBlock = redactSecrets(contextBlock);
  }

  const chatMessages = [
    { role: 'system', content: systemPrompt }
  ];

  if (contextBlock.trim()) {
    chatMessages.push({
      role: 'user',
      content: `Server context (read-only snapshot):\n\n${contextBlock}`
    });
    chatMessages.push({
      role: 'assistant',
      content: 'Understood. I have the server context. What would you like to know?'
    });
  }

  for (const msg of messages || []) {
    if (msg.role === 'user' || msg.role === 'assistant') {
      chatMessages.push({
        role: msg.role,
        content: config.redaction ? redactSecrets(msg.content) : msg.content
      });
    }
  }

  streamSageChat(event.sender, streamId, config, chatMessages);
  return { success: true, streamId };
});

ipcMain.handle('sage-chat-stream-stop', async (event, { streamId }) => {
  stopSageStream(streamId);
  return { success: true };
});
