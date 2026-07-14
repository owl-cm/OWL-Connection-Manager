<p align="center">
  <img src="owl_logo.png" width="150" alt="OWL Logo">
</p>

# OWL - Connection Manager

**OWL** is a premium, high-performance connection manager built with Electron. Designed for power users who demand both aesthetics and functionality, OWL provides a "wow" factor interface with glassmorphism effects, vibrant gradients, and a suite of advanced features for managing remote infrastructure.

> **Secure. Sleek. Seamless.**

---

## 🚀 Why OWL? (The Pros)

- **Unified Workspace**: Stop switching between a terminal, an SFTP client, and a monitoring tool. OWL brings them all into one cohesive, beautiful interface.
- **Zero-Trust Security**: Your credentials never leave your machine. Everything is stored in a local, AES-256 encrypted vault protected by your master password.
- **Native Performance**: Powered by `node-pty` and `xterm.js`, OWL provides a near-native terminal experience with extremely low latency.
- **Privacy First**: No cloud accounts, no telemetry, and no data collection. Your infrastructure data belongs to you.
- **Modern Aesthetics**: A departure from the "boring gray" terminal apps. OWL uses a curated **dark purple** glass theme with smooth transitions and dock accents.

---

## ✨ Key Features in Detail

### 🎨 Premium User Experience (UX)
- **Modern Glassmorphism UI**: Dark purple glass panels, violet accents, and feature-colored dock chips.
- **Interactive Onboarding**: A guided tour for new users to quickly master the interface and discover hidden gems.
- **Responsive Layout**: Optimized for various screen sizes with a collapsible sidebar and flexible workspace.
- **Custom Color Labels**: Color-code your connections (e.g., Red for Production, Green for Dev) for instant visual recognition.
- **Toast Notifications**: Real-time feedback for all actions (success, error, info) with a smooth, non-intrusive design.

### 🔒 Enterprise-Grade Security
- **Secure Credential Vault**: All sensitive data (passwords, passphrases, keys) is encrypted using **AES-256-GCM** with **PBKDF2** key derivation (100,000 iterations).
- **Master Password Protection**: Access your connections only after unlocking the vault. Forgot it? Use **Reset vault** on the unlock screen (deletes all local vault data).
- **Session Auto-Lock**: Configurable idle timeout that automatically locks the application after a period of inactivity.
- **Hardened Security Policies**: Implements strict Content Security Policy (CSP) and Electron security best practices (context isolation, disabled node integration in renderer).
- **Secure IPC Bridge**: All communication between the renderer and main process is handled through a strictly defined preload script.

### 🚀 Advanced SSH & Terminal Capabilities
- **Broadcast Mode**: Synchronize your input across selected active terminal sessions—perfect for executing the same command on multiple servers at once.
- **Bastion/Jump Host Support**: Integrated **ProxyJump** configuration to easily connect to servers behind firewalls.
- **Advanced SSH Options**: Collapsible per-connection OpenSSH `-o` presets (keepalives, compression, agent forwarding, and more), off by default, plus custom options.
- **Automated Login**: Intelligent handling of password and passphrase prompts, including automated "yes" for new host fingerprint confirmations.
- **High-Performance Terminal**: Full support for colors, mouse events, and resizing via `xterm.js`.

### ✨ OWL Sage AI Copilot
- **Multi-provider AI**: OpenAI, Anthropic, Google Gemini, or any LiteLLM / OpenAI-compatible gateway.
- **Context tools**: Attach terminal selection, recent output, or a Diagnose snapshot (metrics, processes, Docker).
- **Encrypted keys**: Provider credentials stay in the vault; optional secret redaction before requests.

### 🐳 Docker Explorer
- Browse containers, images, and volumes over SSH.
- Common container actions and live log streaming from the dock.

### 📂 SFTP File Explorer
- **Graphical File Management**: A dedicated panel for browsing remote directories without leaving the app.
- **Drag-and-Drop Uploads**: Simply drag files from your local machine into the explorer to upload them.
- **Directory Size Calculation**: Real-time calculation of remote directory sizes using optimized `du -sh` commands.
- **Intuitive Navigation**: Breadcrumb-style path navigation with back and refresh capabilities.

### 📊 Real-Time Monitoring
- **Metrics Dashboard**: Live tracking of **CPU**, **RAM**, and **Disk** usage on your connected remote hosts.
- **Remote Process Manager**: A full-featured task manager to view, search, and kill processes on the remote server.
- **System Insights**: Instant visibility into the remote OS version and system uptime.

### 🛠️ Productivity & Management
- **Command Palette**: A searchable interface (`Ctrl+Shift+P` style) for quick access to snippets and common commands.
- **Command Snippets**: Save complex or frequently used commands for one-click execution.
- **Smart Connection Tree**: Organize your servers into nested folders with drag-and-drop reordering and "Smart Cloning" (clones into the same folder).
- **Session Logging**: Automatic logging of terminal sessions with configurable **Log Rotation** (MB-based) to prevent disk bloat.
- **Advanced Log Viewer**: Searchable log history with timeframe filters (Today, Week, Month, Custom Range) and in-log text search.
- **Protocol Support**: Integrated support for **SSH**, **RDP**, and **VNC** protocols.

### 💾 Data Portability
- **Encrypted Backups**: Securely backup your entire configuration using password-protected JSON exports.
- **Seamless Migration**: Automatic migration of legacy plaintext connection data into the secure vault upon first run.

---

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v16 or higher recommended)
- [npm](https://www.npmjs.com/)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/owl-cm/OWL-Connection-Manager.git
   cd OWL-Connection-Manager
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the application:**
   ```bash
   npm start
   ```

---

## 📦 Building for Production

### Debian Package (.deb)
To build a Debian package for Linux:
```bash
npm run build:deb
```
The output will be located in the `dist/installers/` directory.

---

## 🛠️ Built With

- **Electron**: Cross-platform desktop application framework.
- **xterm.js**: High-performance terminal emulator.
- **ssh2**: Robust SSH2 client for Node.js.
- **node-pty**: Native pseudo-terminal support.
- **Crypto**: Node.js native encryption for the secure vault.

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0**.

---

Created with ❤️ by **Mohamed AZGHARI**
