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

// Use secure API from preload script
const { invoke: ipcInvoke, send: ipcSend, on: ipcOn, once: ipcOnce } = window.electronAPI;

// Create wrapper object for compatibility
const ipcRenderer = {
    invoke: ipcInvoke,
    send: ipcSend,
    on: ipcOn,
    once: ipcOnce
};
// Notifications
const notificationContainer = document.getElementById('notification-container');

function showNotification(title, message, type = 'success', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;

    const iconClass = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';

    notification.innerHTML = `
        <div class="notification-icon">
            <i class="fas ${iconClass}"></i>
        </div>
        <div class="notification-content">
            <div class="notification-title">${title}</div>
            <div class="notification-message">${message}</div>
        </div>
    `;

    notificationContainer.appendChild(notification);

    // Auto remove
    const timeout = setTimeout(() => {
        notification.classList.add('hiding');
        setTimeout(() => notification.remove(), 300);
    }, duration);

    notification.onclick = () => {
        clearTimeout(timeout);
        notification.classList.add('hiding');
        setTimeout(() => notification.remove(), 300);
    };
}

let confirmModalResolver = null;

function showConfirm({
    title = 'Are you sure?',
    message = '',
    confirmText = 'Confirm',
    cancelText = 'Cancel',
    variant = 'danger'
} = {}) {
    const confirmModal = document.getElementById('confirm-modal');
    const confirmModalTitle = document.getElementById('confirm-modal-title');
    const confirmModalMessage = document.getElementById('confirm-modal-message');
    const confirmModalOkBtn = document.getElementById('confirm-modal-ok-btn');
    const confirmModalCancelBtn = document.getElementById('confirm-modal-cancel-btn');
    const confirmModalIcon = document.getElementById('confirm-modal-icon');

    return new Promise((resolve) => {
        if (!confirmModal) {
            resolve(false);
            return;
        }

        confirmModalResolver = resolve;
        confirmModalTitle.textContent = title;
        confirmModalMessage.textContent = message;
        confirmModalOkBtn.textContent = confirmText;
        confirmModalCancelBtn.textContent = cancelText;

        confirmModal.classList.toggle('confirm-danger', variant === 'danger');
        confirmModalOkBtn.className = variant === 'primary' ? 'btn-primary' : 'btn-danger';

        if (confirmModalIcon) {
            const iconClass = variant === 'danger' ? 'fa-triangle-exclamation' : 'fa-circle-question';
            confirmModalIcon.classList.toggle('is-danger', variant === 'danger');
            confirmModalIcon.innerHTML = `<i class="fas ${iconClass}"></i>`;
        }

        confirmModal.classList.remove('hidden');
        confirmModalCancelBtn.focus();
    });
}

function closeConfirmModal(result) {
    const confirmModal = document.getElementById('confirm-modal');
    if (confirmModal) confirmModal.classList.add('hidden');
    if (confirmModalResolver) {
        confirmModalResolver(result);
        confirmModalResolver = null;
    }
}

document.addEventListener('keydown', (e) => {
    const confirmModal = document.getElementById('confirm-modal');
    if (e.key === 'Escape' && confirmModal && !confirmModal.classList.contains('hidden')) {
        e.preventDefault();
        closeConfirmModal(false);
    }
});

(function initConfirmModal() {
    const confirmModalOkBtn = document.getElementById('confirm-modal-ok-btn');
    const confirmModalCancelBtn = document.getElementById('confirm-modal-cancel-btn');
    if (confirmModalOkBtn) confirmModalOkBtn.onclick = () => closeConfirmModal(true);
    if (confirmModalCancelBtn) confirmModalCancelBtn.onclick = () => closeConfirmModal(false);
})();

// State
let connections = []; // Now a tree structure
let sessions = {};
let activeSessionId = null;
let editingId = null; // Use ID instead of index
let actionMenuTargetId = null;
let draggedId = null;
let broadcastMode = false;
let selectedBroadcastSessions = new Set();


// DOM Elements
const connectionListEl = document.getElementById('connection-list');
const addBtn = document.getElementById('add-btn');
const addFolderBtn = document.getElementById('add-folder-btn');
const modal = document.getElementById('modal');
const connectionForm = document.getElementById('connection-form');
const saveConnectionBtn = document.getElementById('save-connection-btn');
const cancelBtn = document.getElementById('cancel-btn');
const tabBar = document.getElementById('tab-bar');
const terminalsWrapper = document.getElementById('terminals-wrapper');

const emptyState = document.getElementById('empty-state');
const contextMenu = document.getElementById('context-menu');
const actionMenu = document.getElementById('action-menu');
const tabContextMenu = document.getElementById('tab-context-menu');
const logoutBtn = document.getElementById('logout-btn');
const exportBtn = document.getElementById('export-btn');
const importBtn = document.getElementById('import-btn');
const broadcastModal = document.getElementById('broadcast-modal');
const broadcastConfirmBtn = document.getElementById('broadcast-confirm-btn');
const broadcastCancelBtn = document.getElementById('broadcast-cancel-btn');
const broadcastSelectAll = document.getElementById('broadcast-select-all');
const broadcastSessionList = document.getElementById('broadcast-session-list');
// Vault Elements
const vaultSetupModal = document.getElementById('vault-setup-modal');
const vaultSetupForm = document.getElementById('vault-setup-form');
const vaultSetupPassword = document.getElementById('vault-setup-password');
const vaultSetupConfirm = document.getElementById('vault-setup-confirm');
const mainContainer = document.querySelector('.container');
const vaultUnlockModal = document.getElementById('vault-unlock-modal');
const vaultUnlockForm = document.getElementById('vault-unlock-form');
const vaultUnlockPassword = document.getElementById('vault-unlock-password');
const vaultResetLink = document.getElementById('vault-reset-link');

// Import Decrypt Elements
const importDecryptModal = document.getElementById('import-decrypt-modal');
const importDecryptForm = document.getElementById('import-decrypt-form');
const importDecryptPassword = document.getElementById('import-decrypt-password');
const importDecryptCancel = document.getElementById('import-decrypt-cancel');
let pendingImportFile = null;

// Export Elements
const exportPasswordModal = document.getElementById('export-password-modal');
const exportPasswordForm = document.getElementById('export-password-form');
const exportPasswordInput = document.getElementById('export-password-input');
const exportPasswordCancel = document.getElementById('export-password-cancel');
const exportSelectAll = document.getElementById('export-select-all');
const exportTreeContainer = document.getElementById('export-tree-container');
const exportSearchInput = document.getElementById('export-search-input');
let selectedExportIds = new Set();

// Logs Elements
const toggleLogsBtn = document.getElementById('toggle-logs-btn');
const logsModal = document.getElementById('logs-modal');
const closeLogsBtn = document.getElementById('close-logs-btn');
const logsList = document.getElementById('logs-list');
const logContent = document.getElementById('log-content');
const logContentSearch = document.getElementById('log-content-search');
const logFileSearch = document.getElementById('log-file-search');
const logTimeframeFilter = document.getElementById('log-timeframe-filter');
const customDateRange = document.getElementById('custom-date-range');
const logStartDate = document.getElementById('log-start-date');
const logEndDate = document.getElementById('log-end-date');
const logSearchBar = document.getElementById('log-search-bar');
const logSearchCount = document.getElementById('log-search-count');
const logSearchPrev = document.getElementById('log-search-prev');
const logSearchNext = document.getElementById('log-search-next');

const selectAllLogs = document.getElementById('select-all-logs');
const deleteSelectedLogsBtn = document.getElementById('delete-selected-logs-btn');
let selectedLogFile = null;
let currentLogRawContent = '';
let logSearchMatches = [];
let currentLogSearchIndex = -1;

// File Explorer Elements
const fileExplorer = document.getElementById('file-explorer');
const explorerList = document.getElementById('explorer-list');
const explorerPathInput = document.getElementById('explorer-path');
const toggleExplorerBtn = document.getElementById('toggle-explorer-btn');
const closeExplorerBtn = document.getElementById('close-explorer');
const explorerBackBtn = document.getElementById('explorer-back');
const explorerRefreshBtn = document.getElementById('explorer-refresh');
const explorerUploadBtn = document.getElementById('explorer-upload');
const explorerDirSize = document.getElementById('explorer-dir-size');

// Metrics Elements
const metricsDashboard = document.getElementById('metrics-dashboard');
const cpuBar = document.getElementById('cpu-bar');
const ramBar = document.getElementById('ram-bar');
const diskBar = document.getElementById('disk-bar');
const cpuVal = document.getElementById('cpu-val');
const ramVal = document.getElementById('ram-val');
const diskVal = document.getElementById('disk-val');

// New Elements
const connectionSearch = document.getElementById('connection-search');

const broadcastBtn = document.getElementById('broadcast-btn');
const osInfo = document.getElementById('os-info');
const uptimeInfo = document.getElementById('uptime-info');

const toggleProcessesBtn = document.getElementById('toggle-processes-btn');
const processModal = document.getElementById('process-modal');
const processListBody = document.getElementById('process-list-body');
const refreshProcessesBtn = document.getElementById('refresh-processes');
const closeProcessModalBtn = document.getElementById('close-process-modal');

// Docker Explorer Elements
const toggleDockerBtn = document.getElementById('toggle-docker-btn');
const dockerModal = document.getElementById('docker-modal');
const dockerModalSubtitle = document.getElementById('docker-modal-subtitle');
const dockerResourceList = document.getElementById('docker-resource-list');
const dockerSearch = document.getElementById('docker-search');
const dockerStatusBanner = document.getElementById('docker-status-banner');
const dockerDetailsPanel = document.getElementById('docker-details-panel');
const dockerLogsViewer = document.getElementById('docker-logs-viewer');
const dockerLogsEmpty = document.getElementById('docker-logs-empty');
const dockerViewerTitle = document.getElementById('docker-viewer-title');
const dockerActionBar = document.getElementById('docker-action-bar');
const dockerStatsEl = document.getElementById('docker-stats');
const dockerStatRunning = document.getElementById('docker-stat-running');
const dockerStatContainers = document.getElementById('docker-stat-containers');
const dockerStatImages = document.getElementById('docker-stat-images');
const dockerStatVolumes = document.getElementById('docker-stat-volumes');
const refreshDockerBtn = document.getElementById('refresh-docker');
const closeDockerHeaderBtn = document.getElementById('close-docker-header-btn');
const dockerClearLogsBtn = document.getElementById('docker-clear-logs');
const dockerToggleFollowBtn = document.getElementById('docker-toggle-follow');
const dockerStopLogsBtn = document.getElementById('docker-stop-logs');
const toggleSageBtn = document.getElementById('toggle-sage-btn');
const sagePanel = document.getElementById('sage-panel');
const sageConnectionBadge = document.getElementById('sage-connection-badge');
const sageNotConfigured = document.getElementById('sage-not-configured');
const sagePanelBody = document.getElementById('sage-panel-body');
const sageMessages = document.getElementById('sage-messages');
const sageInput = document.getElementById('sage-input');
const sageSendBtn = document.getElementById('sage-send-btn');
const sageStopBtn = document.getElementById('sage-stop-btn');
const sageClearChatBtn = document.getElementById('sage-clear-chat-btn');
const closeSagePanelBtn = document.getElementById('close-sage-panel-btn');
const sageOpenSettingsBtn = document.getElementById('sage-open-settings-btn');
const sageBtnSelection = document.getElementById('sage-btn-selection');
const sageBtnTerminal = document.getElementById('sage-btn-terminal');
const sageBtnDiagnose = document.getElementById('sage-btn-diagnose');
const sageContextPreview = document.getElementById('sage-context-preview');
const prefSageEnabled = document.getElementById('pref-sage-enabled');
const prefSageProvider = document.getElementById('pref-sage-provider');
const prefSageBaseUrl = document.getElementById('pref-sage-base-url');
const prefSageApiKey = document.getElementById('pref-sage-api-key');
const prefSageModel = document.getElementById('pref-sage-model');
const prefSageRedaction = document.getElementById('pref-sage-redaction');
const sageBaseUrlGroup = document.getElementById('sage-base-url-group');
const sageBaseUrlHint = document.getElementById('sage-base-url-hint');
const sageApiKeyHint = document.getElementById('sage-api-key-hint');
const sageModelHint = document.getElementById('sage-model-hint');

// Settings Elements
const settingsBtn = document.getElementById('settings-btn');
const settingsModal = document.getElementById('settings-modal');
const closeSettingsBtn = document.getElementById('close-settings-btn');
const saveSettingsBtn = document.getElementById('save-settings-btn');
const prefDefaultLogging = document.getElementById('pref-default-logging');
const prefLogRotationSize = document.getElementById('pref-log-rotation-size');
const prefVaultTimeout = document.getElementById('pref-vault-timeout');
const downloadLogBtn = document.getElementById('download-log-btn');

// Connection Form Elements
const authOptions = document.querySelectorAll('.auth-option');
const passwordGroup = document.getElementById('password-group');
const keyGroup = document.getElementById('key-group');
const passphraseGroup = document.getElementById('passphrase-group');
const keyPathInput = document.getElementById('key-path');
const browseKeyBtn = document.getElementById('browse-key-btn');

let currentAuthType = 'password'; // Track current selection
let currentProtocol = 'ssh'; // Track current protocol

let settings = {
    defaultLogging: false,
    logRotationSize: 100, // MB
    vaultTimeout: 0 // Minutes (0 = disabled)
};

let lastActivityTime = Date.now();
let idleInterval = null;

let metricsInterval = null;

let dockerExplorerConnection = null;
let dockerActiveTab = 'containers';
let dockerContainersCache = null;
let dockerImagesCache = null;
let dockerVolumesCache = null;
let dockerSelectedItem = null;
let dockerLogStreamId = null;
let dockerLogsFollow = true;
let dockerTabLoadedAt = {};
const DOCKER_CACHE_TTL_MS = 30000;

const SSH_OPTION_PRESETS = [
    {
        key: 'ServerAliveInterval',
        value: '60',
        description: 'Send keepalive packets every N seconds'
    },
    {
        key: 'ServerAliveCountMax',
        value: '3',
        description: 'Disconnect after this many missed keepalives'
    },
    {
        key: 'ConnectTimeout',
        value: '10',
        description: 'Seconds to wait for the TCP connection'
    },
    {
        key: 'StrictHostKeyChecking',
        value: 'accept-new',
        description: 'Host key policy: yes, no, or accept-new'
    },
    {
        key: 'Compression',
        value: 'yes',
        description: 'Enable compression for slower links'
    },
    {
        key: 'ForwardAgent',
        value: 'yes',
        description: 'Forward local SSH agent to the remote host'
    },
    {
        key: 'TCPKeepAlive',
        value: 'yes',
        description: 'Enable TCP-level keepalive probes'
    },
    {
        key: 'IdentitiesOnly',
        value: 'yes',
        description: 'Only use identities explicitly configured'
    },
    {
        key: 'PreferredAuthentications',
        value: 'publickey,password',
        description: 'Preferred auth method order'
    },
    {
        key: 'PubkeyAuthentication',
        value: 'yes',
        description: 'Allow public key authentication'
    },
    {
        key: 'PasswordAuthentication',
        value: 'yes',
        description: 'Allow password authentication'
    },
    {
        key: 'LogLevel',
        value: 'INFO',
        description: 'SSH verbosity: QUIET, FATAL, ERROR, INFO, VERBOSE'
    }
];

let sshOptionsDraft = [];

const SAGE_PROVIDER_DEFAULTS = {
    litellm: {
        label: 'LiteLLM',
        baseUrl: 'http://localhost:4000/v1',
        model: 'gpt-4o-mini',
        requiresBaseUrl: true,
        baseUrlHint: 'OpenAI-compatible endpoint. LiteLLM default: http://localhost:4000/v1',
        apiKeyHint: 'Stored encrypted in your vault. Sent only to your LiteLLM gateway.',
        modelHint: 'Model name as configured in LiteLLM (e.g. gpt-4o-mini, claude-3-5-sonnet).',
        apiKeyPlaceholder: 'sk-... or your LiteLLM key'
    },
    openai: {
        label: 'OpenAI',
        baseUrl: 'https://api.openai.com/v1',
        model: 'gpt-4o-mini',
        requiresBaseUrl: false,
        baseUrlHint: 'Optional custom OpenAI-compatible endpoint. Leave blank for api.openai.com.',
        apiKeyHint: 'Stored encrypted in your vault. Sent only to OpenAI.',
        modelHint: 'Model name (e.g. gpt-4o-mini, gpt-4.1, o4-mini).',
        apiKeyPlaceholder: 'sk-...'
    },
    anthropic: {
        label: 'Anthropic',
        baseUrl: 'https://api.anthropic.com',
        model: 'claude-sonnet-4-20250514',
        requiresBaseUrl: false,
        baseUrlHint: 'Optional custom Anthropic endpoint. Leave blank for api.anthropic.com.',
        apiKeyHint: 'Stored encrypted in your vault. Sent only to Anthropic.',
        modelHint: 'Model name (e.g. claude-sonnet-4-20250514, claude-opus-4-20250514).',
        apiKeyPlaceholder: 'sk-ant-...'
    },
    gemini: {
        label: 'Google Gemini',
        baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
        model: 'gemini-2.0-flash',
        requiresBaseUrl: false,
        baseUrlHint: 'Optional custom Gemini OpenAI-compatible endpoint.',
        apiKeyHint: 'Stored encrypted in your vault. Sent only to Google Gemini.',
        modelHint: 'Model name (e.g. gemini-2.0-flash, gemini-2.5-pro).',
        apiKeyPlaceholder: 'AIza...'
    }
};

let sageConfig = {
    enabled: false,
    provider: 'litellm',
    baseUrl: SAGE_PROVIDER_DEFAULTS.litellm.baseUrl,
    apiKey: '',
    model: SAGE_PROVIDER_DEFAULTS.litellm.model,
    redaction: true
};
let sageChatHistory = [];
let sagePendingContext = '';
let sageStreamId = null;
let sageIsStreaming = false;

// Helper: Generate ID
function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// Helper: Escape HTML to prevent XSS - properly escape all special characters
function sanitizeHTML(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Helper: Find Item by ID (Recursive)
function findItem(items, id) {
    for (let item of items) {
        if (item.id === id) return item;
        if (item.children) {
            const found = findItem(item.children, id);
            if (found) return found;
        }
    }
    return null;
}

// Helper: Find Parent of Item (Recursive)
function findParent(items, id, parent = null) {
    for (let item of items) {
        if (item.id === id) return { parent, item };
        if (item.children) {
            const found = findParent(item.children, id, item);
            if (found) return found;
        }
    }
    return null;
}

function getSageProviderMeta(provider) {
    return SAGE_PROVIDER_DEFAULTS[provider] || SAGE_PROVIDER_DEFAULTS.litellm;
}

function normalizeSageProvider(provider) {
    return SAGE_PROVIDER_DEFAULTS[provider] ? provider : 'litellm';
}

function updateSageProviderUI(provider, { fillDefaults = false } = {}) {
    const normalized = normalizeSageProvider(provider);
    const meta = getSageProviderMeta(normalized);

    if (prefSageProvider) prefSageProvider.value = normalized;
    if (sageBaseUrlGroup) {
        sageBaseUrlGroup.classList.toggle('hidden', !meta.requiresBaseUrl);
    }
    if (sageBaseUrlHint) sageBaseUrlHint.textContent = meta.baseUrlHint;
    if (sageApiKeyHint) sageApiKeyHint.textContent = meta.apiKeyHint;
    if (sageModelHint) sageModelHint.textContent = meta.modelHint;
    if (prefSageApiKey) prefSageApiKey.placeholder = meta.apiKeyPlaceholder;
    if (prefSageBaseUrl) prefSageBaseUrl.placeholder = meta.baseUrl;
    if (prefSageModel) prefSageModel.placeholder = meta.model;

    if (fillDefaults) {
        if (prefSageBaseUrl) prefSageBaseUrl.value = meta.requiresBaseUrl ? meta.baseUrl : '';
        if (prefSageModel) prefSageModel.value = meta.model;
    }
}

function applySettingsToUI() {
    prefDefaultLogging.checked = settings.defaultLogging;
    prefLogRotationSize.value = settings.logRotationSize;
    if (prefVaultTimeout) prefVaultTimeout.value = settings.vaultTimeout || 0;
    if (prefSageEnabled) prefSageEnabled.checked = !!sageConfig.enabled;
    const provider = normalizeSageProvider(sageConfig.provider);
    updateSageProviderUI(provider);
    if (prefSageBaseUrl) prefSageBaseUrl.value = sageConfig.baseUrl || '';
    if (prefSageApiKey) prefSageApiKey.value = sageConfig.apiKey || '';
    if (prefSageModel) prefSageModel.value = sageConfig.model || getSageProviderMeta(provider).model;
    if (prefSageRedaction) prefSageRedaction.checked = sageConfig.redaction !== false;
}

function updateAuthFields() {
    const type = currentAuthType;

    // Update card active states
    authOptions.forEach(option => {
        if (option.dataset.value === type) {
            option.classList.add('active');
        } else {
            option.classList.remove('active');
        }
    });

    // Show/hide fields with smooth transitions
    if (type === 'password') {
        passwordGroup.classList.remove('hidden');
        keyGroup.classList.add('hidden');
        passphraseGroup.classList.add('hidden');
    } else {
        passwordGroup.classList.add('hidden');
        keyGroup.classList.remove('hidden');
        passphraseGroup.classList.remove('hidden');
    }

    document.getElementById('password').required = (type === 'password');
    keyPathInput.required = (type === 'key');
}

// Auth option click handlers
authOptions.forEach(option => {
    option.addEventListener('click', () => {
        currentAuthType = option.dataset.value;
        updateAuthFields();
    });
});

browseKeyBtn.onclick = async () => {
    const filePath = await ipcRenderer.invoke('open-file-dialog', {
        title: 'Select Private Key',
        filters: [
            { name: 'All Files', extensions: ['*'] },
            { name: 'Keys', extensions: ['key', 'pem', 'id_rsa', 'id_ed25519'] }
        ]
    });
    if (filePath) {
        keyPathInput.value = filePath;
    }
};

// Initialize
// Initialize
async function init() {
    console.log('Init started');
    try {
        // Check Vault Status
        const status = await ipcRenderer.invoke('check-vault-status');
        console.log('Vault status:', status);

        if (status === 'locked') {
            console.log('Vault locked, showing unlock modal');
            mainContainer.classList.add('hidden');
            vaultUnlockModal.classList.remove('hidden');
            vaultUnlockPassword.focus();
            return; // Wait for unlock
        }

        if (status === 'uninitialized' || status === 'plaintext') {
            console.log('Vault uninitialized/plaintext, showing setup modal');
            mainContainer.classList.add('hidden');
            // Force setup for security
            if (vaultSetupModal) {
                vaultSetupModal.classList.remove('hidden');
                vaultSetupPassword.focus();
            } else {
                console.error('Vault setup modal element not found!');
            }
            return; // Wait for setup
        }

        // If unlocked, proceed
        console.log('Vault unlocked, loading connections');
        mainContainer.classList.remove('hidden');
        await loadAndRenderConnections();
    } catch (e) {
        console.error('Init failed:', e);
        mainContainer.classList.add('hidden');
        if (vaultUnlockModal) {
            vaultUnlockModal.classList.remove('hidden');
        }
    } finally {
        document.documentElement.classList.remove('vault-pending');
    }
}

async function loadAndRenderConnections() {
    let rawConnections = await ipcRenderer.invoke('load-connections');

    // Migration: Ensure all items have IDs and structure
    connections = migrateData(rawConnections);
    if (JSON.stringify(connections) !== JSON.stringify(rawConnections)) {
        await ipcRenderer.invoke('save-connections', connections);
    }

    renderTree(connections, connectionListEl);

    // Load Settings
    const savedSettings = localStorage.getItem('owl_settings');
    if (savedSettings) {
        settings = JSON.parse(savedSettings);
    }
    applySettingsToUI();

    await loadSageConfig();

    // Start Idle Timer
    startIdleTimer();
}

// Vault Event Listeners
if (vaultSetupForm) {
    vaultSetupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = vaultSetupPassword.value;
        const confirm = vaultSetupConfirm.value;

        if (password !== confirm) {
            showNotification('Error', 'Passwords do not match', 'error');
            return;
        }

        if (password.length < 8) {
            showNotification('Error', 'Password must be at least 8 characters', 'error');
            return;
        }

        const success = await ipcRenderer.invoke('setup-vault', password);
        if (success) {
            vaultSetupModal.classList.add('hidden');
            mainContainer.classList.remove('hidden');
            await loadAndRenderConnections();
            showNotification('Vault Setup', 'Your vault has been successfully initialized.', 'success');

            // Trigger first-run experience after vault setup
            const isFirstRun = !localStorage.getItem('onboarding_completed');
            if (isFirstRun) {
                // Start onboarding tour
                setTimeout(() => {
                    startOnboarding();
                }, 500);
            }
        } else {
            showNotification('Error', 'Failed to setup vault', 'error');
        }
    });
}

if (vaultUnlockForm) {
    vaultUnlockForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = vaultUnlockPassword.value;

        const success = await ipcRenderer.invoke('unlock-vault', password);
        if (success) {
            vaultUnlockModal.classList.add('hidden');
            mainContainer.classList.remove('hidden');
            vaultUnlockPassword.value = '';
            await loadAndRenderConnections();
            showNotification('Vault Unlocked', 'Welcome back!', 'success');
        } else {
            showNotification('Error', 'Incorrect password', 'error');
            vaultUnlockPassword.value = '';
            vaultUnlockPassword.focus();
        }
    });
}

if (vaultResetLink) {
    vaultResetLink.addEventListener('click', async (e) => {
        e.preventDefault();
        if (await showConfirm({
            title: 'Reset vault?',
            message: 'WARNING: This will delete ALL your saved connections.\n\nThis action cannot be undone.',
            confirmText: 'Reset vault',
            variant: 'danger'
        })) {
            await ipcRenderer.invoke('reset-vault');
            connections = [];
            sageConfig = {
                enabled: false,
                provider: 'litellm',
                baseUrl: SAGE_PROVIDER_DEFAULTS.litellm.baseUrl,
                apiKey: '',
                model: SAGE_PROVIDER_DEFAULTS.litellm.model,
                redaction: true
            };
            if (connectionListEl) connectionListEl.innerHTML = '';
            vaultUnlockModal.classList.add('hidden');
            vaultUnlockPassword.value = '';
            vaultSetupPassword.value = '';
            vaultSetupConfirm.value = '';
            vaultSetupModal.classList.remove('hidden');
            vaultSetupPassword.focus();
            showNotification('Vault Reset', 'All vault data was deleted. Create a new master password.', 'success');
        }
    });
}

// Global click to hide menus
document.addEventListener('click', () => {
    contextMenu.classList.add('hidden');
    actionMenu.classList.add('hidden');
    tabContextMenu.classList.add('hidden');
});

// Handle Resize
window.onresize = () => {
    fitActiveTerminal();
};

// IPC Listeners
ipcRenderer.on('terminal-incoming', (event, { pid, data }) => {
    const sessionId = Object.keys(sessions).find(id => sessions[id].pid === pid);
    if (sessionId) {
        sessions[sessionId].term.write(data);
    }
});

ipcRenderer.on('terminal-created', (event, { pid }) => {
    // Handled locally in createSession via once listener usually, 
    // but we can have a fallback here if needed.
});

// Export/Import Listeners
exportBtn.onclick = () => {
    exportPasswordModal.classList.remove('hidden');
    exportPasswordInput.value = '';

    // Reset selection
    selectedExportIds = new Set();
    // Select all by default (except local terminal)
    const getAllIds = (items) => {
        items.forEach(item => {
            if (item.id !== 'local-terminal') {
                selectedExportIds.add(item.id);
                if (item.children) getAllIds(item.children);
            }
        });
    };
    getAllIds(connections);

    exportSelectAll.checked = true;
    exportSelectAll.indeterminate = false;

    if (exportSearchInput) exportSearchInput.value = '';
    renderExportTree(connections, exportTreeContainer);
    exportPasswordInput.focus();
};

if (exportSearchInput) {
    exportSearchInput.oninput = () => {
        const query = exportSearchInput.value.toLowerCase();
        renderExportTree(connections, exportTreeContainer, query);
    };
}

if (exportPasswordForm) {
    exportPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = exportPasswordInput.value;
        if (password.length < 4) {
            showNotification('Error', 'Password must be at least 4 characters', 'error');
            return;
        }

        if (selectedExportIds.size === 0) {
            showNotification('Error', 'Please select at least one item to export', 'error');
            return;
        }

        // Filter connections based on selection
        const filterConnections = (items) => {
            return items
                .filter(item => selectedExportIds.has(item.id))
                .map(item => {
                    const newItem = { ...item };
                    if (newItem.children) {
                        newItem.children = filterConnections(newItem.children);
                    }
                    return newItem;
                });
        };

        const filteredConnections = filterConnections(connections);

        const success = await ipcRenderer.invoke('export-connections', filteredConnections, password);
        if (success) {
            exportPasswordModal.classList.add('hidden');
            exportPasswordInput.value = '';
        } else {
            // User cancelled save dialog or error
            exportPasswordModal.classList.add('hidden');
        }
    });

    exportPasswordCancel.onclick = () => {
        exportPasswordModal.classList.add('hidden');
        exportPasswordInput.value = '';
    };
}

importBtn.onclick = async () => {
    const result = await ipcRenderer.invoke('import-connections');
    if (!result) return;

    // Check if password is needed
    if (result.status === 'needs_password') {
        pendingImportFile = result.filePath;
        importDecryptModal.classList.remove('hidden');
        importDecryptPassword.value = '';
        importDecryptPassword.focus();
        return;
    }

    // Direct import (plaintext or same-vault encrypted)
    connections = mergeImportedConnections(connections, result);
    await ipcRenderer.invoke('save-connections', connections);
    renderTree(connections, connectionListEl);
    showNotification('Import Successful', 'Connections have been imported and merged.', 'success');
};

// Import Decrypt Logic
if (importDecryptForm) {
    importDecryptForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = importDecryptPassword.value;
        if (!pendingImportFile) return;

        const imported = await ipcRenderer.invoke('decrypt-import-file', pendingImportFile, password);

        if (imported) {
            importDecryptModal.classList.add('hidden');
            connections = mergeImportedConnections(connections, imported);
            await ipcRenderer.invoke('save-connections', connections);
            renderTree(connections, connectionListEl);
            pendingImportFile = null;
            importDecryptPassword.value = '';
            showNotification('Import Successful', 'Connections have been imported and merged.', 'success');
        } else {
            showNotification('Import Failed', 'Failed to decrypt backup. Incorrect password?', 'error');
            importDecryptPassword.value = '';
            importDecryptPassword.focus();
        }
    });

    importDecryptCancel.onclick = () => {
        importDecryptModal.classList.add('hidden');
        pendingImportFile = null;
    };
}

// Search Logic
connectionSearch.oninput = () => {
    const query = connectionSearch.value.toLowerCase();
    renderTree(connections, connectionListEl, query);
};


// Broadcast Logic
broadcastBtn.onclick = () => {
    if (broadcastBtn.classList.contains('disabled')) return;
    if (!broadcastMode) {
        // Reset and populate broadcast selection
        selectedBroadcastSessions = new Set();
        Object.keys(sessions).forEach(id => selectedBroadcastSessions.add(id));

        if (broadcastSelectAll) {
            broadcastSelectAll.checked = true;
            broadcastSelectAll.indeterminate = false;
        }

        renderBroadcastSessionList();
        broadcastModal.classList.remove('hidden');
    } else {
        toggleBroadcastMode();
    }
};

function renderBroadcastSessionList() {
    if (!broadcastSessionList) return;
    broadcastSessionList.innerHTML = '';

    const sessionValues = Object.values(sessions);

    if (sessionValues.length === 0) {
        broadcastSessionList.innerHTML = '<div class="no-sessions-msg">No active terminal sessions found.</div>';
        return;
    }

    const ul = document.createElement('ul');
    ul.className = 'export-tree-list';

    sessionValues.forEach(session => {
        const li = document.createElement('li');
        li.className = 'export-tree-item-wrapper';

        const itemDiv = document.createElement('div');
        itemDiv.className = 'export-tree-item connection';

        const isChecked = selectedBroadcastSessions.has(session.sessionId);

        itemDiv.innerHTML = `
            <label class="checkbox-container" onclick="event.stopPropagation()">
                <input type="checkbox" class="broadcast-item-checkbox" data-id="${session.sessionId}" ${isChecked ? 'checked' : ''}>
                <span class="checkmark"></span>
            </label>
            <span class="item-icon">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            </span>
            <span class="item-label">${sanitizeHTML(session.connection.label)} <small style="opacity: 0.6; margin-left: 8px;">${sanitizeHTML(session.connection.host || '')}</small></span>
        `;

        const checkbox = itemDiv.querySelector('input');

        const toggleSession = () => {
            if (checkbox.checked) {
                selectedBroadcastSessions.add(session.sessionId);
            } else {
                selectedBroadcastSessions.delete(session.sessionId);
            }
            updateBroadcastSelectAllState();
        };

        itemDiv.onclick = () => {
            checkbox.checked = !checkbox.checked;
            toggleSession();
        };

        checkbox.onchange = (e) => {
            e.stopPropagation();
            toggleSession();
        };

        li.appendChild(itemDiv);
        ul.appendChild(li);
    });

    broadcastSessionList.appendChild(ul);
}

function updateBroadcastSelectAllState() {
    if (!broadcastSelectAll) return;
    const allSessions = Object.keys(sessions);
    const allSelected = allSessions.length > 0 && allSessions.every(id => selectedBroadcastSessions.has(id));
    const someSelected = allSessions.some(id => selectedBroadcastSessions.has(id));

    broadcastSelectAll.checked = allSelected;
    broadcastSelectAll.indeterminate = !allSelected && someSelected;
}

if (broadcastSelectAll) {
    broadcastSelectAll.onchange = () => {
        if (broadcastSelectAll.checked) {
            Object.keys(sessions).forEach(id => selectedBroadcastSessions.add(id));
        } else {
            selectedBroadcastSessions.clear();
        }
        renderBroadcastSessionList();
    };
}

broadcastConfirmBtn.onclick = () => {
    toggleBroadcastMode();
    broadcastModal.classList.add('hidden');
};

broadcastCancelBtn.onclick = () => {
    broadcastModal.classList.add('hidden');
};

function toggleBroadcastMode() {
    broadcastMode = !broadcastMode;
    broadcastBtn.classList.toggle('active', broadcastMode);

    // Update tab highlighting
    Object.values(sessions).forEach(session => {
        if (broadcastMode && selectedBroadcastSessions.has(session.sessionId)) {
            session.tabEl.classList.add('broadcast-active');
        } else {
            session.tabEl.classList.remove('broadcast-active');
        }
    });

    if (broadcastMode) {
        showNotification('Broadcast Activated', `Keystrokes will be sent to ${selectedBroadcastSessions.size} terminals.`, 'warning');
    } else {
        showNotification('Broadcast Deactivated', 'Keystrokes will only be sent to the active terminal.', 'info');
    }
}

// Process Manager Listeners
toggleProcessesBtn.onclick = () => {
    if (toggleProcessesBtn.classList.contains('disabled')) return;
    if (!activeSessionId) return;
    processModal.classList.remove('hidden');
    loadProcesses();
};

// Logs Listeners
toggleLogsBtn.onclick = () => {
    logsModal.classList.remove('hidden');
    loadLogs();
};

closeLogsBtn.addEventListener('click', () => {
    logsModal.classList.add('hidden');
});

deleteSelectedLogsBtn.onclick = async () => {
    const selectedCheckboxes = document.querySelectorAll('.log-checkbox:checked');
    if (selectedCheckboxes.length === 0) return;

    const filenames = Array.from(selectedCheckboxes).map(cb => cb.dataset.filename);
    if (await showConfirm({
        title: 'Delete log files?',
        message: `Delete ${filenames.length} selected log file(s)?`,
        confirmText: 'Delete',
        variant: 'danger'
    })) {
        const success = await ipcRenderer.invoke('delete-logs', filenames);
        if (success) {
            if (filenames.includes(selectedLogFile)) {
                selectedLogFile = null;
                logContent.innerHTML = '<div class="log-empty-state">Select a log to view</div>';
            }
            loadLogs();
        }
    }
};

selectAllLogs.onchange = () => {
    const checkboxes = document.querySelectorAll('.log-checkbox');
    checkboxes.forEach(cb => cb.checked = selectAllLogs.checked);
    updateDeleteSelectedBtnVisibility();
};

logContentSearch.oninput = () => {
    performLogSearch();
};

logFileSearch.oninput = () => {
    loadLogs();
};

logTimeframeFilter.onchange = () => {
    const isCustom = logTimeframeFilter.value === 'custom';
    customDateRange.classList.toggle('hidden', !isCustom);
    loadLogs();
};

logStartDate.onchange = () => loadLogs();
logEndDate.onchange = () => loadLogs();

// In-log search toolbar
// Log search is now always visible
logSearchPrev.onclick = () => navigateLogSearch(-1);
logSearchNext.onclick = () => navigateLogSearch(1);

// Ctrl+F shortcut
window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'f' && !logsModal.classList.contains('hidden')) {
        e.preventDefault();
        logContentSearch.focus();
    }
});

refreshProcessesBtn.onclick = () => loadProcesses();
closeProcessModalBtn.onclick = () => processModal.classList.add('hidden');
document.getElementById('close-process-header-btn').onclick = () => processModal.classList.add('hidden');

// Docker Explorer Listeners
toggleDockerBtn.onclick = () => {
    if (toggleDockerBtn.classList.contains('disabled')) return;
    if (!activeSessionId) return;
    const session = sessions[activeSessionId];
    if (!session || !isDockerCapableConnection(session.connection)) return;
    openDockerExplorer(session.connection);
};

refreshDockerBtn.onclick = () => refreshDockerView(true);
closeDockerHeaderBtn.onclick = () => closeDockerExplorer();
dockerSearch.oninput = () => renderDockerResourceList();

dockerClearLogsBtn.onclick = () => {
    dockerLogsViewer.textContent = '';
    dockerLogsEmpty.classList.add('hidden');
};

dockerToggleFollowBtn.onclick = () => {
    dockerLogsFollow = !dockerLogsFollow;
    dockerToggleFollowBtn.classList.toggle('active', dockerLogsFollow);
};

dockerStopLogsBtn.onclick = () => stopDockerLogStream();

document.querySelectorAll('.docker-tab').forEach(tab => {
    tab.onclick = async () => {
        dockerActiveTab = tab.dataset.tab;
        document.querySelectorAll('.docker-tab').forEach(t => t.classList.toggle('active', t === tab));
        dockerSelectedItem = null;
        stopDockerLogStream();
        resetDockerViewer();
        await loadDockerTab(dockerActiveTab);
    };
});

ipcRenderer.on('docker-logs-stream-data', (event, { streamId, chunk }) => {
    if (streamId !== dockerLogStreamId) return;
    dockerLogsEmpty.classList.add('hidden');
    dockerLogsViewer.textContent += chunk;
    if (dockerLogsFollow) {
        dockerLogsViewer.scrollTop = dockerLogsViewer.scrollHeight;
    }
});

ipcRenderer.on('docker-logs-stream-end', (event, { streamId }) => {
    if (streamId !== dockerLogStreamId) return;
    dockerLogStreamId = null;
    dockerLogsViewer.textContent += '\n[stream ended]\n';
});

// OWL Sage Listeners
if (toggleSageBtn) {
    toggleSageBtn.onclick = () => {
        if (toggleSageBtn.classList.contains('disabled')) return;
        toggleSagePanel();
    };
}
if (closeSagePanelBtn) closeSagePanelBtn.onclick = () => closeSagePanel();
if (sageOpenSettingsBtn) {
    sageOpenSettingsBtn.onclick = () => {
        applySettingsToUI();
        settingsModal.classList.remove('hidden');
    };
}
if (sageSendBtn) sageSendBtn.onclick = () => sendSageMessage();
if (sageStopBtn) sageStopBtn.onclick = () => stopSageStream();
if (sageClearChatBtn) sageClearChatBtn.onclick = () => clearSageChat();
if (sageBtnSelection) sageBtnSelection.onclick = () => attachSageSelection();
if (sageBtnTerminal) sageBtnTerminal.onclick = () => attachSageTerminalContext();
if (sageBtnDiagnose) sageBtnDiagnose.onclick = () => attachSageDiagnoseContext();
if (prefSageProvider) {
    prefSageProvider.onchange = () => {
        updateSageProviderUI(prefSageProvider.value, { fillDefaults: true });
    };
}
if (sageInput) {
    sageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendSageMessage();
        }
    });
}

ipcRenderer.on('sage-stream-chunk', (event, { streamId, chunk }) => {
    if (streamId !== sageStreamId) return;
    appendSageStreamChunk(chunk);
});

ipcRenderer.on('sage-stream-end', (event, { streamId }) => {
    if (streamId !== sageStreamId) return;
    finishSageStream();
});

ipcRenderer.on('sage-stream-error', (event, { streamId, error }) => {
    if (streamId !== sageStreamId) return;
    finishSageStream(error);
});

window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.code === 'KeyI') {
        e.preventDefault();
        if (!toggleSageBtn || toggleSageBtn.classList.contains('disabled')) return;
        toggleSagePanel(true);
    }
});

// Settings Listeners
settingsBtn.onclick = () => {
    applySettingsToUI();
    settingsModal.classList.remove('hidden');
};

closeSettingsBtn.onclick = () => {
    settingsModal.classList.add('hidden');
};

saveSettingsBtn.onclick = async () => {
    settings.defaultLogging = prefDefaultLogging.checked;
    settings.logRotationSize = parseInt(prefLogRotationSize.value) || 100;
    settings.vaultTimeout = parseFloat(prefVaultTimeout.value) || 0;

    localStorage.setItem('owl_settings', JSON.stringify(settings));

    const newApiKey = prefSageApiKey ? prefSageApiKey.value.trim() : '';
    const provider = normalizeSageProvider(prefSageProvider ? prefSageProvider.value : sageConfig.provider);
    const meta = getSageProviderMeta(provider);
    sageConfig = {
        enabled: prefSageEnabled ? prefSageEnabled.checked : false,
        provider,
        baseUrl: prefSageBaseUrl ? prefSageBaseUrl.value.trim() : '',
        apiKey: newApiKey || sageConfig.apiKey,
        model: prefSageModel ? prefSageModel.value.trim() || meta.model : meta.model,
        redaction: prefSageRedaction ? prefSageRedaction.checked : true
    };
    await ipcRenderer.invoke('save-sage-config', sageConfig);
    updateDockButtonsState();
    updateSagePanelState();

    // Restart idle timer
    startIdleTimer();

    settingsModal.classList.add('hidden');
    showNotification('Settings', 'Preferences saved.', 'success');
};

// --- Auto-Lock Logic ---
function startIdleTimer() {
    if (idleInterval) clearInterval(idleInterval);

    // Reset activity timestamp
    lastActivityTime = Date.now();

    if (settings.vaultTimeout > 0) {
        // Use a shorter interval if timeout is very short (e.g. 10s)
        const interval = settings.vaultTimeout < 1 ? 5000 : 60000;
        idleInterval = setInterval(checkIdleTime, interval);
        checkIdleTime();
    }
}

function checkIdleTime() {
    if (settings.vaultTimeout <= 0) return;

    const idleTime = Date.now() - lastActivityTime;
    const timeoutMs = settings.vaultTimeout * 60 * 1000;

    if (idleTime >= timeoutMs) {
        lockVault();
    }
}

async function lockVault() {
    if (sagePanel) {
        sagePanel.classList.add('hidden');
        document.body.classList.remove('sage-panel-open');
    }

    document.querySelectorAll('.modal').forEach((m) => m.classList.add('hidden'));

    Object.keys(sessions).slice().forEach((id) => closeSession(id));
    activeSessionId = null;

    await ipcRenderer.invoke('lock-vault');

    mainContainer.classList.add('hidden');
    connections = [];
    connectionListEl.innerHTML = '';

    if (idleInterval) clearInterval(idleInterval);

    vaultUnlockModal.classList.remove('hidden');
    vaultUnlockPassword.value = '';
    vaultUnlockPassword.focus();
}

if (logoutBtn) {
    logoutBtn.onclick = async () => {
        if (!await showConfirm({
            title: 'Lock session?',
            message: 'Lock vault and end your session?\n\nAll open terminals will be closed. You will need your master password to unlock.',
            confirmText: 'Log out',
            variant: 'danger'
        })) {
            return;
        }
        lockVault();
    };
}

// Track Activity
function resetActivity() {
    lastActivityTime = Date.now();
}

window.addEventListener('mousemove', resetActivity);
window.addEventListener('keydown', resetActivity);
window.addEventListener('click', resetActivity);
window.addEventListener('scroll', resetActivity);

downloadLogBtn.onclick = async () => {
    if (!selectedLogFile) return;
    await ipcRenderer.invoke('download-log', selectedLogFile);
};



// File Explorer Listeners
toggleExplorerBtn.onclick = () => {
    if (toggleExplorerBtn.classList.contains('disabled')) return;
    const isCollapsed = fileExplorer.classList.toggle('collapsed');
    toggleExplorerBtn.classList.toggle('active', !isCollapsed);

    // Resize terminal after transition
    setTimeout(fitActiveTerminal, 400);

    if (!isCollapsed) {
        const session = sessions[activeSessionId];
        if (session) {
            loadRemoteFiles(session.currentPath);
            updateDirSize();
        }
    }
};


closeExplorerBtn.onclick = () => {
    fileExplorer.classList.add('collapsed');
    toggleExplorerBtn.classList.remove('active');
    setTimeout(fitActiveTerminal, 400);
};

explorerBackBtn.onclick = () => {
    const session = sessions[activeSessionId];
    if (!session || session.currentPath === '/') return;
    const parts = session.currentPath.split('/').filter(p => p);
    parts.pop();
    session.currentPath = '/' + parts.join('/');
    loadRemoteFiles(session.currentPath);
    updateDirSize();
};

explorerRefreshBtn.onclick = () => {
    const session = sessions[activeSessionId];
    if (session) {
        loadRemoteFiles(session.currentPath);
        updateDirSize();
    }
};

explorerUploadBtn.onclick = async () => {
    const session = sessions[activeSessionId];
    if (!session) {
        showNotification('Upload Failed', 'No active session', 'error');
        return;
    }

    try {
        const success = await ipcRenderer.invoke('sftp-upload', {
            connection: session.connection,
            remoteDir: session.currentPath
        });

        if (success) {
            showNotification('Upload Successful', 'File uploaded successfully', 'success');
            loadRemoteFiles(session.currentPath);
        } else {
            showNotification('Upload Cancelled', 'File upload was cancelled', 'error');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showNotification('Upload Failed', error.message || 'Failed to upload file', 'error');
    }
};

// Initial dock button state
updateDockButtonsState();


// Render Export Tree
function renderExportTree(items, container, query = '') {
    container.innerHTML = '';
    const ul = document.createElement('ul');
    ul.className = 'export-tree-list';

    // Filter out local terminal from export selection
    let exportableItems = items.filter(item => item.id !== 'local-terminal');

    // Apply search filter if query exists
    if (query) {
        exportableItems = exportableItems.filter(item => {
            const matchesLabel = item.label.toLowerCase().includes(query);
            const matchesHost = item.host && item.host.toLowerCase().includes(query);

            if (matchesLabel || matchesHost) return true;

            if (item.type === 'folder' && item.children) {
                // Show folder if any of its children match
                return item.children.some(child => {
                    const childMatchesLabel = child.label.toLowerCase().includes(query);
                    const childMatchesHost = child.host && child.host.toLowerCase().includes(query);
                    return childMatchesLabel || childMatchesHost;
                });
            }
            return false;
        });
    }

    exportableItems.forEach(item => {
        const li = document.createElement('li');
        li.className = 'export-tree-item-wrapper';

        const itemDiv = document.createElement('div');
        itemDiv.className = `export-tree-item ${item.type}`;

        const isChecked = selectedExportIds.has(item.id);

        itemDiv.innerHTML = `
            <label class="checkbox-container" onclick="event.stopPropagation()">
                <input type="checkbox" class="export-item-checkbox" data-id="${item.id}" ${isChecked ? 'checked' : ''}>
                <span class="checkmark"></span>
            </label>
            <span class="item-icon">
                ${item.type === 'folder' ?
                '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>' :
                '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>'}
            </span>
            <span class="item-label">${sanitizeHTML(item.label)}</span>
        `;

        const checkbox = itemDiv.querySelector('input');

        // Toggle on item click
        itemDiv.onclick = (e) => {
            checkbox.checked = !checkbox.checked;
            toggleExportItem(item, checkbox.checked);
            updateExportSelectAllState();
            renderExportTree(connections, exportTreeContainer);
        };

        checkbox.onchange = (e) => {
            e.stopPropagation();
            toggleExportItem(item, checkbox.checked);
            updateExportSelectAllState();
            renderExportTree(connections, exportTreeContainer);
        };

        li.appendChild(itemDiv);

        if (item.children && item.children.length > 0) {
            const childrenUl = document.createElement('ul');
            childrenUl.className = 'export-tree-children';
            renderExportTree(item.children, childrenUl, query);
            li.appendChild(childrenUl);
        }

        ul.appendChild(li);
    });

    container.appendChild(ul);
}

function toggleExportItem(item, isChecked) {
    if (isChecked) {
        selectedExportIds.add(item.id);
    } else {
        selectedExportIds.delete(item.id);
    }

    if (item.children) {
        item.children.forEach(child => toggleExportItem(child, isChecked));
    }

    // Update parent state
    updateParentSelectionState(connections, item.id);
}

function updateParentSelectionState(items, childId) {
    for (const item of items) {
        if (item.children) {
            const hasChild = item.children.some(c => c.id === childId || (c.children && findChildRecursive(c.children, childId)));
            if (hasChild) {
                // Check if all children are selected
                const allSelected = item.children.every(c => selectedExportIds.has(c.id));
                const someSelected = item.children.some(c => selectedExportIds.has(c.id));

                if (allSelected) {
                    selectedExportIds.add(item.id);
                } else {
                    selectedExportIds.delete(item.id);
                }
                updateParentSelectionState(connections, item.id);
                return;
            }
            updateParentSelectionState(item.children, childId);
        }
    }
}

function findChildRecursive(children, id) {
    return children.some(c => c.id === id || (c.children && findChildRecursive(c.children, id)));
}

function updateExportSelectAllState() {
    const exportableItems = [];
    const collectExportable = (items) => {
        items.forEach(item => {
            if (item.id !== 'local-terminal') {
                exportableItems.push(item);
                if (item.children) collectExportable(item.children);
            }
        });
    };
    collectExportable(connections);

    const allSelected = exportableItems.every(item => selectedExportIds.has(item.id));
    const someSelected = exportableItems.some(item => selectedExportIds.has(item.id));

    exportSelectAll.checked = allSelected;
    exportSelectAll.indeterminate = !allSelected && someSelected;
}

exportSelectAll.addEventListener('change', () => {
    const isChecked = exportSelectAll.checked;
    const updateAll = (items) => {
        items.forEach(item => {
            if (item.id !== 'local-terminal') {
                if (isChecked) selectedExportIds.add(item.id);
                else selectedExportIds.delete(item.id);
                if (item.children) updateAll(item.children);
            }
        });
    };
    updateAll(connections);
    renderExportTree(connections, exportTreeContainer);
});

function updateDockButtonsState() {
    const hasActiveSession = !!activeSessionId;
    toggleExplorerBtn.classList.toggle('disabled', !hasActiveSession);
    broadcastBtn.classList.toggle('disabled', !hasActiveSession);
    toggleProcessesBtn.classList.toggle('disabled', !hasActiveSession);
    toggleDockerBtn.classList.toggle('disabled', !hasActiveSession);
    if (toggleSageBtn) {
        toggleSageBtn.classList.toggle('disabled', !hasActiveSession || !isSageConfigured());
    }
}

function migrateData(data, isRoot = true) {
    if (isRoot) {
        // Ensure "Local Terminal" exists and is at the top
        let localTerminal = data.find(item => item.id === 'local-terminal');
        if (!localTerminal) {
            localTerminal = {
                id: 'local-terminal',
                label: 'Local Terminal',
                type: 'connection',
                protocol: 'local',
                isDefault: true
            };
            data.unshift(localTerminal);
        } else {
            // Ensure it's at the top
            data = data.filter(item => item.id !== 'local-terminal');
            data.unshift(localTerminal);
        }
    } else {
        // Ensure "Local Terminal" is NOT in subfolders
        data = data.filter(item => item.id !== 'local-terminal');
    }

    // If it's a flat list without IDs, convert it
    return data.map(item => {
        if (!item.id) item.id = generateId();
        if (!item.type) item.type = 'connection';
        if (item.children) item.children = migrateData(item.children, false); // Recurse as non-root
        return item;
    });
}

function collectConnectionIds(items, ids = new Set()) {
    for (const item of items) {
        if (item?.id) ids.add(item.id);
        if (item?.children) collectConnectionIds(item.children, ids);
    }
    return ids;
}

function prepareImportedItems(items, existingIds) {
    const prepared = [];

    for (const item of items) {
        if (!item || item.id === 'local-terminal') continue;

        const copy = JSON.parse(JSON.stringify(item));
        copy.id = generateId();
        existingIds.add(copy.id);

        if (!copy.type) copy.type = 'connection';
        if (copy.children) {
            copy.children = prepareImportedItems(copy.children, existingIds);
        }

        prepared.push(copy);
    }

    return prepared;
}

function normalizeImportedData(importedRaw) {
    if (Array.isArray(importedRaw)) return importedRaw;
    if (importedRaw?.connections && Array.isArray(importedRaw.connections)) {
        return importedRaw.connections;
    }
    return [];
}

function mergeImportedConnections(existing, importedRaw) {
    const importedArray = normalizeImportedData(importedRaw);
    if (importedArray.length === 0) return existing;

    const existingIds = collectConnectionIds(existing);
    const prepared = prepareImportedItems(importedArray, existingIds);

    if (prepared.length === 0) return existing;

    const localTerminal = existing.find(item => item.id === 'local-terminal');
    const rest = existing.filter(item => item.id !== 'local-terminal');

    return localTerminal ? [localTerminal, ...rest, ...prepared] : [...existing, ...prepared];
}

// Render Tree
function getListIconHtml(item) {
    if (item.type === 'folder') {
        return `<span class="list-folder-glyph" aria-hidden="true">~/</span>`;
    }

    const proto = item.protocol || 'ssh';
    const prompts = {
        ssh: '>_',
        local: '$_',
        rdp: '>_',
        vnc: '>_'
    };
    const glyph = prompts[proto] || '>_';
    return `<span class="list-icon-glyph" aria-hidden="true">${glyph}</span>`;
}

function getListIconType(item) {
    if (item.type === 'folder') return 'folder';
    return item.protocol || 'ssh';
}

function renderTree(items, container, query = '', parentColor = null) {
    container.innerHTML = '';

    const filteredItems = items.filter(item => {
        if (!query) return true;

        const matches = item.label.toLowerCase().includes(query);
        if (matches) return true;

        if (item.type === 'folder' && item.children) {
            return item.children.some(child => child.label.toLowerCase().includes(query));
        }
        return false;
    });

    filteredItems.forEach(item => {
        const li = document.createElement('li');
        li.dataset.id = item.id;
        li.draggable = item.id !== 'local-terminal';

        // Drag Events
        li.addEventListener('dragstart', handleDragStart);
        li.addEventListener('dragover', handleDragOver);
        li.addEventListener('drop', handleDrop);
        li.addEventListener('dragend', handleDragEnd);
        li.addEventListener('dragleave', handleDragLeave);

        if (item.type === 'folder') {
            li.className = 'folder-item';
            if (item.expanded) li.classList.add('expanded');

            const folderColor = item.color || parentColor;
            if (folderColor) {
                li.style.setProperty('--item-color', folderColor);
            }

            li.innerHTML = `
        <div class="folder-header">
          <div class="folder-content">
            <i class="fas fa-chevron-right list-expander" aria-hidden="true"></i>
            <span class="list-icon" data-type="folder">
              ${getListIconHtml(item)}
            </span>
            <span class="list-label">${sanitizeHTML(item.label)}</span>
          </div>
          <div class="folder-actions-group">
            <button class="list-menu-btn add-child-btn" title="Add Connection to Folder" aria-label="Add connection to folder">
              <i class="fas fa-plus"></i>
            </button>
          </div>
        </div>
        <ul class="folder-children"></ul>
      `;

            // Folder Context Menu (Right-click)
            li.querySelector('.folder-header').addEventListener('contextmenu', (e) => {
                e.preventDefault();
                showActionMenu(e, item.id);
            });

            // Add Child Action
            li.querySelector('.add-child-btn').onclick = (e) => {
                e.stopPropagation();
                openModal(null, 'connection', item.id);
            };

            // Toggle Expand
            li.querySelector('.folder-header').onclick = (e) => {
                if (e.target.closest('.list-menu-btn')) return;
                item.expanded = !item.expanded;
                renderTree(connections, connectionListEl); // Re-render to show/hide children
                ipcRenderer.invoke('save-connections', connections);
            };

            // Double-click to Edit Folder
            li.querySelector('.folder-header').ondblclick = (e) => {
                e.stopPropagation();
                openModal(item.id, 'folder');
            };

            // Render Children
            const childrenContainer = li.querySelector('.folder-children');
            if (item.children) {
                renderTree(item.children, childrenContainer, query, folderColor);
            }

        } else {
            // Connection Item
            li.className = 'connection-item';

            const connectionColor = parentColor || '';
            if (connectionColor) {
                li.style.setProperty('--item-color', connectionColor);
            }

            const iconType = getListIconType(item);

            li.innerHTML = `
        <div class="connection-header">
          <div class="connection-label-wrap">
            <span class="list-icon" data-type="${sanitizeHTML(iconType)}">
              ${getListIconHtml(item)}
            </span>
            <span class="list-label">${sanitizeHTML(item.label)}</span>
          </div>
          <button class="list-menu-btn connection-menu-btn" title="Connection actions" aria-label="Connection actions">
            <i class="fas fa-ellipsis-v"></i>
          </button>
        </div>
        <div class="sidebar-metrics" id="metrics-${sanitizeHTML(item.id)}">
          <div class="mini-bar"><div class="mini-bar-fill mini-bar-cpu"></div></div>
          <div class="mini-bar"><div class="mini-bar-fill mini-bar-ram"></div></div>
          <div class="mini-bar"><div class="mini-bar-fill mini-bar-disk"></div></div>
        </div>
      `;

            li.querySelector('.connection-menu-btn').onclick = (e) => {
                e.stopPropagation();
                showActionMenu(e, item.id);
            };

            li.onclick = (e) => {
                if (e.target.closest('.connection-menu-btn')) return;
                const sessionItem = { ...item };
                if (connectionColor) sessionItem.color = connectionColor;
                createSession(sessionItem);
            };



            // Right-click Context Menu
            li.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                showActionMenu(e, item.id);
            });
        }

        container.appendChild(li);
    });
}

// Drag & Drop Logic
function handleDragStart(e) {
    draggedId = this.dataset.id;
    e.dataTransfer.effectAllowed = 'move';
    this.classList.add('dragging');
    e.stopPropagation(); // Prevent bubbling
}

function handleDragOver(e) {
    e.preventDefault(); // Necessary to allow dropping
    e.stopPropagation();

    const targetLi = e.currentTarget;
    if (targetLi.dataset.id === draggedId) return;

    // Visual cues
    const rect = targetLi.getBoundingClientRect();
    const offset = e.clientY - rect.top;

    // Decide if dropping inside (folder) or before/after
    const item = findItem(connections, targetLi.dataset.id);

    targetLi.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');

    // Radical: Prevent Local Terminal from being dropped inside folders
    const isLocalTerminal = draggedId === 'local-terminal';

    if (item.type === 'folder' && offset > 10 && offset < rect.height - 10 && !isLocalTerminal) {
        targetLi.classList.add('drag-over'); // Drop inside
    } else if (offset < rect.height / 2) {
        targetLi.classList.add('drag-over-top');
    } else {
        targetLi.classList.add('drag-over-bottom');
    }
}

function handleDragLeave(e) {
    this.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom');
}

function handleDragEnd(e) {
    this.classList.remove('dragging');
    document.querySelectorAll('.drag-over, .drag-over-top, .drag-over-bottom')
        .forEach(el => el.classList.remove('drag-over', 'drag-over-top', 'drag-over-bottom'));
}

async function handleDrop(e) {
    e.stopPropagation();
    const targetId = this.dataset.id;
    if (draggedId === targetId) return;

    // Find dragged item and remove it from old location
    const draggedInfo = findParent(connections, draggedId);
    const targetInfo = findParent(connections, targetId);

    if (!draggedInfo || !targetInfo) return;

    const draggedItem = draggedInfo.item;
    const targetItem = targetInfo.item;

    // Radical: Prevent Local Terminal from being moved into folders
    if (draggedId === 'local-terminal') {
        const isDropInsideFolder = targetItem.type === 'folder' && this.classList.contains('drag-over');
        const isTargetInsideFolder = targetInfo.parent !== null;

        if (isDropInsideFolder || isTargetInsideFolder) {
            renderTree(connections, connectionListEl);
            return;
        }
    }

    // Remove from old parent
    if (draggedInfo.parent) {
        draggedInfo.parent.children = draggedInfo.parent.children.filter(c => c.id !== draggedId);
    } else {
        connections = connections.filter(c => c.id !== draggedId);
    }

    // Determine drop position
    const rect = this.getBoundingClientRect();
    const offset = e.clientY - rect.top;

    if (targetItem.type === 'folder' && this.classList.contains('drag-over')) {
        // Drop inside folder
        if (!targetItem.children) targetItem.children = [];
        targetItem.children.push(draggedItem);
        targetItem.expanded = true;
    } else {
        // Drop before or after
        const parentList = targetInfo.parent ? targetInfo.parent.children : connections;
        const targetIndex = parentList.findIndex(c => c.id === targetId);

        if (this.classList.contains('drag-over-top')) {
            parentList.splice(targetIndex, 0, draggedItem);
        } else {
            parentList.splice(targetIndex + 1, 0, draggedItem);
        }
    }

    await ipcRenderer.invoke('save-connections', connections);
    renderTree(connections, connectionListEl);
}



class TerminalInstance {
    constructor(sessionId, connection) {
        this.sessionId = sessionId;
        this.connection = connection;
        this.pid = null;
        this.logging = false;
        this.currentPath = '.';

        // Create Tab
        this.tabEl = document.createElement('div');
        this.tabEl.className = 'tab';
        if (connection.color) {
            this.tabEl.style.setProperty('--tab-color', connection.color);
        }
        this.tabEl.innerHTML = `
            <span class="broadcast-icon"><i class="fas fa-tower-broadcast"></i></span>
            <span class="tab-title">${sanitizeHTML(connection.label)}</span>
            <span class="tab-close">✕</span>
        `;

        // Create Container
        this.containerEl = document.createElement('div');
        this.containerEl.className = 'terminal-instance';

        // Initialize xterm
        this.term = window.terminalFactory.create({
            theme: { background: '#000000' },
            fontFamily: 'monospace',
            fontSize: 14,
            allowProposedApi: true,
            copyOnSelection: true
        });

        this.resizeObserver = new ResizeObserver(() => {
            this.fit();
        });

        this.setupListeners();
    }

    setupListeners() {
        this.tabEl.onclick = (e) => {
            if (e.target.classList.contains('tab-close')) {
                e.stopPropagation();
                closeSession(this.sessionId);
            } else {
                activateSession(this.sessionId);
            }
        };

        this.tabEl.oncontextmenu = (e) => {
            e.preventDefault();
            showTabContextMenu(e.clientX, e.clientY, this.sessionId);
        };

        this.containerEl.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            showContextMenu(e.clientX, e.clientY, this.sessionId);
        });

        this.term.onData(data => {
            if (this.pid) {
                // Only broadcast if broadcast mode is on AND this terminal is part of the selected group
                if (broadcastMode && selectedBroadcastSessions.has(this.sessionId)) {
                    Object.values(sessions).forEach(session => {
                        if (session.pid && selectedBroadcastSessions.has(session.sessionId)) {
                            ipcRenderer.send('terminal-write', { pid: session.pid, data });
                        }
                    });
                } else {
                    // Normal behavior: only write to this terminal
                    ipcRenderer.send('terminal-write', { pid: this.pid, data });
                }
            }
        });

        this.term.onResize(({ cols, rows }) => {
            if (this.pid) {
                ipcRenderer.send('terminal-resize', { pid: this.pid, cols, rows });
            }
        });

        // Robust Copy on Selection
        this.term.onSelectionChange(() => {
            if (this.term.hasSelection()) {
                const selection = this.term.getSelection();
                if (selection && selection.length > 0) {
                    navigator.clipboard.writeText(selection);
                }
            }
        });

        // Keyboard Shortcuts
        this.term.attachCustomKeyEventHandler((e) => {
            if (e.type === 'keydown') {
                const isCtrl = e.ctrlKey;
                const isShift = e.shiftKey;
                const isAlt = e.altKey;

                // Ctrl+Shift+C: Copy
                if (isCtrl && isShift && e.code === 'KeyC') {
                    const selection = this.term.getSelection();
                    if (selection) {
                        navigator.clipboard.writeText(selection);
                    }
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }

                // Ctrl+Shift+V: Paste
                if (isCtrl && isShift && e.code === 'KeyV') {
                    e.preventDefault();
                    e.stopPropagation();
                    navigator.clipboard.readText().then(text => {
                        if (this.pid) {
                            ipcRenderer.send('terminal-write', { pid: this.pid, data: text });
                        }
                    });
                    return false;
                }

                // Ctrl+Alt+P: Paste Password
                if (isCtrl && isAlt && e.code === 'KeyP') {
                    if (this.connection.password && this.pid) {
                        ipcRenderer.send('terminal-write', { pid: this.pid, data: this.connection.password });
                    }
                    return false;
                }

                // Ctrl+Alt+L: Copy Password
                if (isCtrl && isAlt && e.code === 'KeyL') {
                    if (this.connection.password) {
                        navigator.clipboard.writeText(this.connection.password);
                        setTimeout(() => {
                            navigator.clipboard.writeText('');
                        }, 30000);
                    }
                    return false;
                }
            }
            return true;
        });
    }

    attach(tabBar, terminalsWrapper) {
        tabBar.appendChild(this.tabEl);
        terminalsWrapper.appendChild(this.containerEl);
        this.term.open(this.containerEl);
        this.resizeObserver.observe(this.containerEl);
    }

    activate() {
        this.tabEl.classList.add('active');
        this.containerEl.classList.add('active');

        // Radical: Force a layout reflow
        void this.containerEl.offsetWidth;

        // Use requestAnimationFrame to ensure layout is updated
        requestAnimationFrame(() => {
            this.fit(true); // Aggressive fit
            this.term.focus();
        });
    }

    deactivate() {
        this.tabEl.classList.remove('active');
        this.containerEl.classList.remove('active');
    }

    fit(aggressive = false) {
        // Only fit if the container is actually in the DOM and has size
        if (this.containerEl.offsetParent !== null && this.containerEl.offsetWidth > 0) {
            const dims = this.term.proposeDimensions();

            if (dims) {
                this.term.resize(dims.cols, dims.rows);
            } else {
                // Radical: Manual calculation if xterm fails to propose dimensions
                const manualCols = Math.floor(this.containerEl.offsetWidth / 9);
                const manualRows = Math.floor(this.containerEl.offsetHeight / 18);
                this.term.resize(manualCols, manualRows);
            }

            // Radical: If aggressive, retry if we suspect a default size on a large container
            if (aggressive && this.cols === 80 && this.rows === 24 && this.containerEl.offsetWidth > 800) {
                setTimeout(() => this.fit(false), 100);
            }
        }
    }

    get cols() { return this.term.getCols(); }
    get rows() { return this.term.getRows(); }

    dispose() {
        this.resizeObserver.disconnect();
        this.tabEl.remove();
        this.containerEl.remove();
        this.term.dispose();
    }
}


// Session Management (Updated for Color)
function createSession(connection) {
    // Handle Non-SSH Protocols
    if (connection.protocol && connection.protocol !== 'ssh' && connection.protocol !== 'local') {
        ipcRenderer.invoke('launch-protocol', connection);
        return;
    }

    const sessionId = Date.now().toString();
    const session = new TerminalInstance(sessionId, connection);
    sessions[sessionId] = session;

    session.attach(tabBar, terminalsWrapper);

    // Radical: Ensure dashboard is visible BEFORE activation
    emptyState.style.display = 'none';
    metricsDashboard.classList.remove('hidden');

    activateSession(sessionId);

    // Register listener BEFORE sending creation request
    ipcRenderer.once('terminal-created', (event, { pid }) => {
        if (sessions[sessionId]) {
            sessions[sessionId].pid = pid;

            // Handle Default Logging
            if (settings.defaultLogging) {
                sessions[sessionId].logging = true;
                ipcRenderer.send('toggle-logging', {
                    pid: pid,
                    sessionId,
                    label: connection.label,
                    enabled: true,
                    rotationLimitMB: settings.logRotationSize
                });
            }

            // Robust multi-stage sizing synchronization
            const syncSize = (attempts) => {
                if (!sessions[sessionId] || attempts <= 0) return;

                sessions[sessionId].fit(true);
                const cols = sessions[sessionId].cols;
                const rows = sessions[sessionId].rows;

                if (cols > 0 && rows > 0) {
                    ipcRenderer.send('terminal-resize', {
                        pid: sessions[sessionId].pid,
                        cols: cols,
                        rows: rows
                    });
                }
                sessions[sessionId].term.focus();

                if (attempts > 1) {
                    setTimeout(() => syncSize(attempts - 1), 300);
                }
            };

            setTimeout(() => syncSize(5), 100);
        }
    });

    // Wait for layout to settle, fonts to load, and container to have STABLE size
    let creationAttempts = 0;
    let lastWidth = 0;
    let lastHeight = 0;
    let stableCount = 0;

    const waitForSizeAndCreate = async () => {
        creationAttempts++;

        // Wait for fonts on first attempt
        if (creationAttempts === 1) {
            await document.fonts.ready;
        }

        const width = session.containerEl.offsetWidth;
        const height = session.containerEl.offsetHeight;

        // Force reflow
        void session.containerEl.offsetWidth;

        if (width > 50 && height > 50) {
            if (width === lastWidth && height === lastHeight) {
                stableCount++;
            } else {
                stableCount = 0;
                lastWidth = width;
                lastHeight = height;
            }

            // Wait for 3 consecutive identical measurements to ensure stability
            if (stableCount >= 3) {
                session.fit(true);
                ipcRenderer.send('terminal-create', {
                    connection: connection.id === 'local-terminal' ? null : connection,
                    cols: session.cols || 80,
                    rows: session.rows || 24
                });
                return;
            }
        }

        if (creationAttempts < 40) { // Wait up to 2 seconds
            setTimeout(waitForSizeAndCreate, 50);
        } else {
            // Fallback: create with whatever we have
            session.fit(true);
            ipcRenderer.send('terminal-create', {
                connection: connection.id === 'local-terminal' ? null : connection,
                cols: session.cols || 80,
                rows: session.rows || 24
            });
        }
    };
    waitForSizeAndCreate();
}

function activateSession(sessionId) {
    activeSessionId = sessionId;

    // Deactivate all sessions
    Object.values(sessions).forEach(s => s.deactivate());

    if (sessions[sessionId]) {
        const session = sessions[sessionId];
        session.activate();

        // Reset UI immediately for the new session
        resetMetricsUI();
        osInfo.innerText = 'OS: ...';
        uptimeInfo.innerText = 'Up: ...';

        explorerPathInput.value = session.currentPath;
        explorerDirSize.innerText = '...';

        emptyState.style.display = 'none';
        metricsDashboard.classList.remove('hidden');
        startMetricsPolling();

        // Enable dock buttons
        toggleExplorerBtn.classList.remove('disabled');
        broadcastBtn.classList.remove('disabled');
        toggleProcessesBtn.classList.remove('disabled');
        toggleDockerBtn.classList.toggle('disabled', !isDockerCapableConnection(session.connection));
        updateDockButtonsState();

        // If explorer is open, refresh its content for the new session
        if (!fileExplorer.classList.contains('collapsed')) {
            loadRemoteFiles(session.currentPath);
            updateDirSize();
        }
    } else {
        emptyState.style.display = 'flex';
        fileExplorer.classList.add('collapsed');
        metricsDashboard.classList.add('hidden');
        toggleExplorerBtn.classList.remove('active');
        stopMetricsPolling();

        // Disable dock buttons
        toggleExplorerBtn.classList.add('disabled');
        broadcastBtn.classList.add('disabled');
        toggleProcessesBtn.classList.add('disabled');
        toggleDockerBtn.classList.add('disabled');
        updateDockButtonsState();

        // Deactivate broadcast if it was on
        if (broadcastMode) {
            toggleBroadcastMode();
        }
    }
}

function startMetricsPolling() {
    stopMetricsPolling();
    updateMetrics(); // Initial call
    metricsInterval = setInterval(updateMetrics, 5000); // Every 5 seconds
}

function stopMetricsPolling() {
    if (metricsInterval) {
        clearInterval(metricsInterval);
        metricsInterval = null;
    }
}

function resetMetricsUI() {
    cpuBar.style.width = '0%';
    cpuVal.innerText = '0%';
    ramBar.style.width = '0%';
    ramVal.innerText = '0%';
    diskBar.style.width = '0%';
    diskVal.innerText = '0%';
}

async function updateMetrics() {
    // Update metrics for ALL open sessions in parallel to ensure speed
    const sessionIds = Object.keys(sessions);
    await Promise.all(sessionIds.map(async (sessionId) => {
        const session = sessions[sessionId];
        if (!session) return;

        try {
            const metrics = await ipcRenderer.invoke('get-metrics', {
                connection: session.connection
            });

            if (metrics) {
                // If this is the active session, update the main dashboard
                if (sessionId === activeSessionId) {
                    updateBar(cpuBar, cpuVal, metrics.cpu);
                    updateBar(ramBar, ramVal, metrics.ram);
                    updateBar(diskBar, diskVal, metrics.disk);

                    osInfo.innerText = `OS: ${metrics.os}`;
                    uptimeInfo.innerText = `Up: ${metrics.uptime}`;
                }

                // Always update sidebar metrics for this session
                const sidebarMetrics = document.getElementById(`metrics-${session.connection.id}`);
                if (sidebarMetrics) {
                    updateSidebarMiniBar(sidebarMetrics.querySelector('.mini-bar-cpu'), metrics.cpu);
                    updateSidebarMiniBar(sidebarMetrics.querySelector('.mini-bar-ram'), metrics.ram);
                    updateSidebarMiniBar(sidebarMetrics.querySelector('.mini-bar-disk'), metrics.disk);
                }
            }
        } catch (err) {
            console.error(`Failed to update metrics for session ${sessionId}:`, err);
        }
    }));
}

async function updateDirSize() {
    const session = sessions[activeSessionId];
    if (!session || fileExplorer.classList.contains('collapsed')) return;

    explorerDirSize.innerText = '...';
    try {
        const size = await ipcRenderer.invoke('get-dir-size', {
            connection: session.connection,
            path: session.currentPath
        });
        explorerDirSize.innerText = size;
    } catch (err) {
        explorerDirSize.innerText = 'N/A';
    }
}

function updateBar(bar, valEl, value) {
    bar.style.width = `${value}%`;
    valEl.innerText = `${Math.round(value)}%`;

    // Threshold colors
    bar.classList.remove('low', 'medium', 'high');
    if (value < 60) bar.classList.add('low');
    else if (value < 80) bar.classList.add('medium');
    else bar.classList.add('high');
}

function updateSidebarMiniBar(bar, value) {
    bar.style.width = `${value}%`;
    // Optional: mini bars could also change color but might be too busy
}

async function loadRemoteFiles(path) {
    const session = sessions[activeSessionId];
    if (!session) return;

    explorerList.innerHTML = `
        <div class="explorer-loading">
            <div class="spinner"></div>
            <span>Fetching files...</span>
        </div>
    `;
    session.currentPath = path || '.';
    explorerPathInput.value = session.currentPath;

    try {
        const files = await ipcRenderer.invoke('sftp-list', {
            connection: session.connection,
            path: session.currentPath
        });

        renderExplorerList(files);
    } catch (err) {
        explorerList.innerHTML = `
            <div class="explorer-loading">
                <span class="text-danger">Error: ${sanitizeHTML(err.message)}</span>
                <button class="btn-primary" id="explorer-retry-btn">Retry</button>
            </div>
        `;
        document.getElementById('explorer-retry-btn').onclick = () => loadRemoteFiles(session.currentPath);
    }
}

function renderExplorerList(files) {
    explorerList.innerHTML = '';

    // Sort: Directories first, then files
    files.sort((a, b) => {
        if (a.type === b.type) return a.name.localeCompare(b.name);
        return a.type === 'directory' ? -1 : 1;
    });

    files.forEach(file => {
        if (file.name === '.' || file.name === '..') return;

        const item = document.createElement('div');
        item.className = `explorer-item ${file.type === 'directory' ? 'directory' : ''}`;
        const icon = file.type === 'directory'
            ? `<svg viewBox="0 0 24 24" width="18" height="18" fill="#FACC15" xmlns="http://www.w3.org/2000/svg"><path d="M20 18c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2V7c0-1.1.9-2 2-2h3l2 2h7c1.1 0 2 .9 2 2v9z"/></svg>`
            : getFileIcon(file.name);

        item.innerHTML = `
            <span class="item-icon">${icon}</span>
            <span class="item-name">${sanitizeHTML(file.name)}</span>
            <span class="item-size">${file.type === 'file' ? formatSize(file.size) : ''}</span>
            <div class="item-actions">
                ${file.type === 'file' ? '<button class="btn-icon download-btn" title="Download"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg></button>' : ''}
            </div>
        `;

        item.onclick = (e) => {
            if (e.target.closest('.download-btn')) return;
            const session = sessions[activeSessionId];
            if (!session) return;

            if (file.type === 'directory') {
                const newPath = session.currentPath.endsWith('/')
                    ? session.currentPath + file.name
                    : session.currentPath + '/' + file.name;
                loadRemoteFiles(newPath);
                updateDirSize();
            }
        };

        const downloadBtn = item.querySelector('.download-btn');
        if (downloadBtn) {
            downloadBtn.onclick = async (e) => {
                e.stopPropagation();
                const session = sessions[activeSessionId];
                const remotePath = session.currentPath.endsWith('/')
                    ? session.currentPath + file.name
                    : session.currentPath + '/' + file.name;

                await ipcRenderer.invoke('sftp-download', {
                    connection: session.connection,
                    remotePath
                });
            };
        }

        explorerList.appendChild(item);
    });
}

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const icons = {
        'js': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#FACC15" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>',
        'json': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>',
        'html': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f43f5e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline><line x1="14" y1="2" x2="10" y2="22"></line></svg>',
        'css': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>',
        'png': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>',
        'jpg': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>',
        'jpeg': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>',
        'svg': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>',
        'md': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>',
        'txt': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>',
        'sh': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>',
        'py': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>',
        'zip': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v3m18 8v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3"></path><path d="M3 12h18"></path><path d="M12 3v18"></path></svg>',
        'gz': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v3m18 8v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3"></path><path d="M3 12h18"></path><path d="M12 3v18"></path></svg>',
        'tar': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v3m18 8v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3"></path><path d="M3 12h18"></path><path d="M12 3v18"></path></svg>',
        'pdf': '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f43f5e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><path d="M9 15l2 2 4-4"></path></svg>'
    };
    return icons[ext] || '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>';
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function closeSession(sessionId) {
    const session = sessions[sessionId];
    if (!session) return;

    // Reset sidebar metrics for this connection
    const sidebarMetrics = document.getElementById(`metrics-${session.connection.id}`);
    if (sidebarMetrics) {
        sidebarMetrics.querySelectorAll('.mini-bar div').forEach(bar => {
            bar.style.width = '0%';
        });
    }

    session.dispose();
    delete sessions[sessionId];
    selectedBroadcastSessions.delete(sessionId);

    if (activeSessionId === sessionId) {
        const remainingIds = Object.keys(sessions);
        if (remainingIds.length > 0) {
            activateSession(remainingIds[remainingIds.length - 1]);
        } else {
            activateSession(null);
        }
    }
}

// Context Menu Logic (Same as before)
function showContextMenu(x, y, sessionId) {
    contextMenu.classList.remove('hidden');
    actionMenu.classList.add('hidden');
    tabContextMenu.classList.add('hidden');

    const menuHeight = contextMenu.offsetHeight;
    const menuWidth = contextMenu.offsetWidth;

    let top = y;
    let left = x;

    if (top + menuHeight > window.innerHeight) {
        top = y - menuHeight;
    }
    if (left + menuWidth > window.innerWidth) {
        left = x - menuWidth;
    }

    contextMenu.style.left = `${left}px`;
    contextMenu.style.top = `${top}px`;

    const session = sessions[sessionId];

    document.getElementById('ctx-copy').onclick = () => {
        const selection = session.term.getSelection();
        navigator.clipboard.writeText(selection);
        contextMenu.classList.add('hidden');
        session.term.focus();
    };

    document.getElementById('ctx-paste').onclick = async () => {
        const text = await navigator.clipboard.readText();
        if (session.pid) {
            ipcRenderer.send('terminal-write', { pid: session.pid, data: text });
        }
        contextMenu.classList.add('hidden');
        session.term.focus();
    };

    document.getElementById('ctx-copy-pass').onclick = () => {
        if (session.connection.password) {
            navigator.clipboard.writeText(session.connection.password);
        }
        contextMenu.classList.add('hidden');
        session.term.focus();
    };

    document.getElementById('ctx-paste-pass').onclick = () => {
        if (session.connection.password && session.pid) {
            ipcRenderer.send('terminal-write', { pid: session.pid, data: session.connection.password });
        }
        contextMenu.classList.add('hidden');
        session.term.focus();
    };
}

// Action Menu Logic
function showActionMenu(e, id) {
    actionMenu.classList.remove('hidden');
    contextMenu.classList.add('hidden');
    tabContextMenu.classList.add('hidden');

    const menuHeight = actionMenu.offsetHeight;
    const menuWidth = actionMenu.offsetWidth;

    let top, left;

    if (e.type === 'contextmenu') {
        top = e.clientY;
        left = e.clientX;
    } else {
        const rect = e.target.getBoundingClientRect();
        top = rect.bottom + 5;
        left = rect.left;

        // Ensure it doesn't go off bottom
        if (top + menuHeight > window.innerHeight) {
            top = rect.top - menuHeight - 5;
        }
    }

    // Final boundary checks for both cases
    if (top + menuHeight > window.innerHeight) {
        top = window.innerHeight - menuHeight - 10;
    }
    if (left + menuWidth > window.innerWidth) {
        left = window.innerWidth - menuWidth - 10;
    }

    actionMenu.style.left = `${left}px`;
    actionMenu.style.top = `${top}px`;

    actionMenuTargetId = id;

    const isLocalTerminal = actionMenuTargetId === 'local-terminal';
    const editBtn = document.getElementById('action-edit');
    const cloneBtn = document.getElementById('action-clone');
    const deleteBtn = document.getElementById('action-delete');
    const dockerBtn = document.getElementById('action-docker');
    const item = findItem(connections, actionMenuTargetId);
    const isFolder = item && item.type === 'folder';
    const dockerCapable = isDockerCapableConnection(item);

    if (isLocalTerminal) {
        editBtn.classList.add('disabled');
        cloneBtn.classList.add('disabled');
        deleteBtn.classList.add('disabled');
        editBtn.onclick = null;
        cloneBtn.onclick = null;
        deleteBtn.onclick = null;

        dockerBtn.classList.remove('disabled');
        dockerBtn.onclick = () => {
            actionMenu.classList.add('hidden');
            openDockerExplorer(item);
        };
    } else if (isFolder) {
        editBtn.classList.remove('disabled');
        cloneBtn.classList.remove('disabled');
        deleteBtn.classList.remove('disabled');
        dockerBtn.classList.add('disabled');
        dockerBtn.onclick = null;

        editBtn.onclick = () => {
            openModal(actionMenuTargetId, 'folder');
            actionMenu.classList.add('hidden');
        };

        cloneBtn.onclick = () => {
            cloneItem(actionMenuTargetId);
            actionMenu.classList.add('hidden');
        };

        deleteBtn.onclick = async () => {
            actionMenu.classList.add('hidden');
            if (!await showConfirm({
                title: 'Delete folder?',
                message: 'Are you sure you want to delete this folder and all its contents?\n\nThis action cannot be undone.',
                confirmText: 'Delete',
                variant: 'danger'
            })) return;
            await deleteConnectionById(actionMenuTargetId);
        };
    } else {
        editBtn.classList.remove('disabled');
        cloneBtn.classList.remove('disabled');
        deleteBtn.classList.remove('disabled');

        if (dockerCapable) {
            dockerBtn.classList.remove('disabled');
            dockerBtn.onclick = () => {
                actionMenu.classList.add('hidden');
                openDockerExplorer(item);
            };
        } else {
            dockerBtn.classList.add('disabled');
            dockerBtn.onclick = null;
        }

        editBtn.onclick = () => {
            openModal(actionMenuTargetId);
            actionMenu.classList.add('hidden');
        };

        cloneBtn.onclick = () => {
            cloneItem(actionMenuTargetId);
            actionMenu.classList.add('hidden');
        };

        deleteBtn.onclick = async () => {
            const isFolderConn = item && item.type === 'folder';
            actionMenu.classList.add('hidden');
            if (!await showConfirm({
                title: isFolderConn ? 'Delete folder?' : 'Delete connection?',
                message: isFolderConn
                    ? 'Are you sure you want to delete this folder and all its contents?\n\nThis action cannot be undone.'
                    : 'Are you sure you want to delete this connection?\n\nThis action cannot be undone.',
                confirmText: 'Delete',
                variant: 'danger'
            })) return;
            await deleteConnectionById(actionMenuTargetId);
        };
    }
}

// Tab Context Menu Logic
function showTabContextMenu(x, y, sessionId) {
    tabContextMenu.classList.remove('hidden');
    contextMenu.classList.add('hidden');
    actionMenu.classList.add('hidden');

    const menuHeight = tabContextMenu.offsetHeight;
    const menuWidth = tabContextMenu.offsetWidth;

    let top = y;
    let left = x;

    if (top + menuHeight > window.innerHeight) {
        top = y - menuHeight;
    }
    if (left + menuWidth > window.innerWidth) {
        left = x - menuWidth;
    }

    tabContextMenu.style.left = `${left}px`;
    tabContextMenu.style.top = `${top}px`;

    document.getElementById('tab-ctx-close').onclick = () => {
        closeSession(sessionId);
        tabContextMenu.classList.add('hidden');
    };

    document.getElementById('tab-ctx-close-all').onclick = () => {
        const sessionIds = Object.keys(sessions);
        sessionIds.forEach(id => closeSession(id));
        tabContextMenu.classList.add('hidden');
    };

    const session = sessions[sessionId];
    const logItem = document.getElementById('tab-ctx-log');
    logItem.innerText = session.logging ? 'Stop Logging' : 'Start Logging';
    logItem.onclick = () => {
        session.logging = !session.logging;
        ipcRenderer.send('toggle-logging', {
            pid: session.pid,
            sessionId,
            label: session.connection.label,
            enabled: session.logging,
            rotationLimitMB: settings.logRotationSize
        });
        tabContextMenu.classList.add('hidden');
    };
}

async function deleteConnectionById(id) {
    if (!id) return;
    const info = findParent(connections, id);
    if (info) {
        if (info.parent) {
            info.parent.children = info.parent.children.filter(c => c.id !== id);
        } else {
            connections = connections.filter(c => c.id !== id);
        }
        await ipcRenderer.invoke('save-connections', connections);
        renderTree(connections, connectionListEl);
    }
}

// Modal Logic
function openModal(id = null, type = 'connection', parentId = null) {
    connectionForm.reset(); // Always start with a clean form
    editingId = id;
    let item = null;

    if (id) {
        item = findItem(connections, id);
        if (item) {
            type = item.type || 'connection';
        }
    }

    // Store type and parentId for submit handler immediately
    connectionForm.dataset.type = type;
    connectionForm.dataset.parentId = parentId || '';

    modal.classList.remove('hidden');

    // Reset Tabs
    const segmentBtns = document.querySelectorAll('.segment-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    segmentBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => {
        c.classList.remove('active');
        c.classList.add('hidden');
    });

    // Default to Connection tab
    const connTabBtn = document.querySelector('[data-tab="connection-tab"]');
    if (connTabBtn) connTabBtn.classList.add('active');
    const connTab = document.getElementById('connection-tab');
    if (connTab) {
        connTab.classList.remove('hidden');
        connTab.classList.add('active');
    }

    // Show/Hide fields based on type
    const isFolder = type === 'folder';

    // Toggle Segmented Control for Folders
    const modalHeader = modal.querySelector('.modal-header-compact');
    if (modalHeader) {
        const segControl = modalHeader.querySelector('.segmented-control');
        if (segControl) segControl.style.display = isFolder ? 'none' : 'flex';
    }

    // Toggle fields visibility
    const hostEl = document.getElementById('host');
    if (hostEl) hostEl.parentElement.style.display = isFolder ? 'none' : 'block';

    const userEl = document.getElementById('user');
    if (userEl) userEl.parentElement.style.display = isFolder ? 'none' : 'block';

    const portEl = document.getElementById('port');
    if (portEl) portEl.parentElement.style.display = isFolder ? 'none' : 'block';

    // Protocol Selector Visibility
    const protocolSelector = document.querySelector('.protocol-selector');
    if (protocolSelector) {
        protocolSelector.parentElement.style.display = isFolder ? 'none' : 'block';
    }

    // Show/hide auth selector and fields
    const authSelector = document.querySelector('.auth-type-selector');
    if (authSelector) {
        authSelector.parentElement.style.display = isFolder ? 'none' : 'block';
    }

    const authFieldsContainer = document.querySelector('.auth-fields-container');
    if (authFieldsContainer) {
        authFieldsContainer.style.display = isFolder ? 'none' : 'block';
    }

    const sshOptionsGroup = document.getElementById('ssh-options-group');
    if (sshOptionsGroup) {
        sshOptionsGroup.style.display = isFolder ? 'none' : 'block';
    }

    const colorGroup = document.getElementById('color-group');
    if (colorGroup) {
        colorGroup.style.display = isFolder ? 'block' : 'none';
    }

    if (!isFolder) {
        updateAuthFields();
        updateProtocolFields();
    }

    // Clear values for folders
    if (isFolder) {
        if (hostEl) hostEl.value = '';
        if (userEl) userEl.value = '';
    }

    // Set title and button text
    const title = id ? (isFolder ? 'Edit Folder' : 'Edit Connection') : (isFolder ? 'Add Folder' : 'Add Connection');
    const h3 = modal.querySelector('h3');
    if (h3) h3.innerText = title;

    if (saveConnectionBtn) saveConnectionBtn.innerText = id ? 'Save Changes' : (isFolder ? 'Create Folder' : 'Create Connection');

    if (id && item) {
        document.getElementById('label').value = item.label;
        if (!isFolder) {
            document.getElementById('host').value = item.host;
            document.getElementById('user').value = item.user;
            document.getElementById('port').value = item.port;
            currentAuthType = item.authType || 'password';
            currentProtocol = item.protocol || 'ssh'; // Load protocol

            document.getElementById('password').value = item.password || '';
            keyPathInput.value = item.keyPath || '';
            document.getElementById('passphrase').value = item.passphrase || '';

            // Bastion fields
            const bHost = document.getElementById('bastion-host');
            if (bHost) bHost.value = item.bastionHost || '';

            const bUser = document.getElementById('bastion-user');
            if (bUser) bUser.value = item.bastionUser || '';

            const bKey = document.getElementById('bastion-key-path');
            if (bKey) bKey.value = item.bastionKeyPath || '';

            loadSshOptionsDraft(item.sshOptions);
            updateBastionStatusDot();
            updateAuthFields();
            updateProtocolFields();
        }

        const color = item.color || '';
        const radio = document.querySelector(`input[name="color"][value="${color}"]`);
        if (radio) radio.checked = true;
        else {
            const noneColor = document.getElementById('color-none');
            if (noneColor) noneColor.checked = true;
        }
    } else {
        const noneColor = document.getElementById('color-none');
        if (noneColor) noneColor.checked = true;

        currentAuthType = 'password'; // Reset to default
        currentProtocol = 'ssh'; // Reset to default
        loadSshOptionsDraft([]);
        updateAuthFields();
        updateProtocolFields();

        // Reset Bastion
        const bHost = document.getElementById('bastion-host');
        if (bHost) bHost.value = '';
        const bUser = document.getElementById('bastion-user');
        if (bUser) bUser.value = '';
        const bKey = document.getElementById('bastion-key-path');
        if (bKey) bKey.value = '';
        updateBastionStatusDot();
    }
}

async function cloneItem(id) {
    const item = findItem(connections, id);
    if (!item) return;

    const newItem = JSON.parse(JSON.stringify(item)); // Deep copy
    newItem.id = generateId();
    newItem.label = `${newItem.label} (Copy)`;

    // If it's a folder, we need to regenerate IDs for children too
    if (newItem.children) {
        newItem.children = migrateData(newItem.children); // Re-assign IDs
    }

    const info = findParent(connections, id);
    if (info && info.parent) {
        info.parent.children.push(newItem);
    } else {
        connections.push(newItem);
    }

    await ipcRenderer.invoke('save-connections', connections);
    renderTree(connections, connectionListEl);
}

addBtn.onclick = () => {
    openModal(null, 'connection');
};

addFolderBtn.onclick = () => {
    openModal(null, 'folder');
};

cancelBtn.onclick = () => {
    modal.classList.add('hidden');
    connectionForm.reset();
    editingId = null;
};

saveConnectionBtn.onclick = async () => {
    let type = connectionForm.dataset.type || 'connection';
    if (editingId) {
        const item = findItem(connections, editingId);
        if (item) type = item.type;
    }

    const isFolder = type === 'folder';

    // Manual Validation
    const label = document.getElementById('label').value.trim();
    if (!label) {
        showNotification('Validation Error', 'Please enter a label.', 'error');
        return;
    }

    let host, user;
    if (type === 'connection') {
        host = document.getElementById('host').value.trim();
        user = document.getElementById('user').value.trim();
        if (!host || !user) {
            showNotification('Validation Error', 'Please enter both host and user.', 'error');
            return;
        }
    }

    const newItem = {
        id: editingId || generateId(),
        type: type,
        label: label
    };

    if (isFolder) {
        const colorRadio = document.querySelector('input[name="color"]:checked');
        newItem.color = colorRadio ? colorRadio.value : '';
    }

    if (type === 'connection') {
        newItem.host = document.getElementById('host').value;
        newItem.user = document.getElementById('user').value;
        newItem.port = document.getElementById('port').value;
        newItem.protocol = currentProtocol; // Save Protocol
        newItem.authType = currentAuthType;
        newItem.password = document.getElementById('password').value;
        newItem.keyPath = keyPathInput.value;
        newItem.passphrase = document.getElementById('passphrase').value;

        // Bastion Fields
        newItem.bastionHost = document.getElementById('bastion-host').value;
        newItem.bastionUser = document.getElementById('bastion-user').value;
        newItem.bastionKeyPath = document.getElementById('bastion-key-path').value;
        newItem.sshOptions = getSshOptionsForSave();
    } else if (type === 'folder') {
        newItem.children = editingId ? (findItem(connections, editingId).children || []) : [];
        newItem.expanded = true;
    }

    if (editingId) {
        // Update existing
        const info = findParent(connections, editingId);
        if (info) {
            if (info.parent) {
                const idx = info.parent.children.findIndex(c => c.id === editingId);
                info.parent.children[idx] = newItem;
            } else {
                const idx = connections.findIndex(c => c.id === editingId);
                connections[idx] = newItem;
            }
        }
    } else {
        // Add new
        const parentId = connectionForm.dataset.parentId;
        if (parentId) {
            const parentItem = findItem(connections, parentId);
            if (parentItem) {
                if (!parentItem.children) parentItem.children = [];
                parentItem.children.push(newItem);
                parentItem.expanded = true;
            } else {
                connections.push(newItem);
            }
        } else {
            connections.push(newItem);
        }
    }

    await ipcRenderer.invoke('save-connections', connections);
    renderTree(connections, connectionListEl);

    modal.classList.add('hidden');
    connectionForm.reset();
    editingId = null;
};


function startOnboarding() {
    const tour = new OnboardingTour();
    tour.start();
}

class OnboardingTour {
    constructor() {
        this.currentStep = 0;
        this.steps = [
            {
                title: "Welcome to OWL",
                text: "Your premium SSH connection manager. Let's take a quick tour of the main features.",
                target: ".welcome-container",
                position: "center"
            },
            {
                title: "Settings & Preferences",
                text: "Customize your experience, manage and configure global application preferences here.",
                target: "#settings-btn",
                position: "right"
            },
            {
                title: "Data Portability",
                text: "Export your connections to a secure backup or import existing data from other devices.",
                target: "#export-btn",
                position: "right"
            },
            {
                title: "Organize with Folders",
                text: "Create folders to group your connections by project, environment, or client.",
                target: "#add-folder-btn",
                position: "right"
            },
            {
                title: "New Connection",
                text: "Add a new SSH, RDP, or VNC connection to your workspace.",
                target: "#add-btn",
                position: "right"
            },
            {
                title: "Connections & Folders",
                text: "Manage your servers in the sidebar. Use folders to stay organized and drag-and-drop to move connections.",
                target: ".sidebar",
                position: "right"
            },
            {
                title: "Search Connections",
                text: "Quickly find any server by name using the sidebar search bar.",
                target: ".sidebar-search",
                position: "right"
            },
            {
                title: "Quick Actions",
                text: "Quickly add connections or import your existing data from the welcome screen.",
                target: ".quick-actions-grid",
                position: "top"
            },
            {
                title: "File Explorer",
                text: "Browse, upload, and download files via SFTP with a modern graphical interface.",
                target: "#toggle-explorer-btn",
                position: "top"
            },
            {
                title: "Command Snippets",
                text: "Save frequently used commands as snippets. Use the palette to search and execute them instantly.",
                target: "#toggle-snippets-btn",
                position: "top"
            },
            {
                title: "Broadcast Mode",
                text: "Send your keystrokes to all active terminals at once. Perfect for managing clusters.",
                target: "#broadcast-btn",
                position: "top"
            },
            {
                title: "Process Manager",
                text: "Monitor and manage remote processes directly from the UI without typing 'top' or 'ps'.",
                target: "#toggle-processes-btn",
                position: "top"
            },
            {
                title: "Session Logs",
                text: "Keep track of your terminal history. View, search, and download logs for every session.",
                target: "#toggle-logs-btn",
                position: "top"
            },
            {
                title: "Live Metrics",
                text: "Real-time CPU, RAM, and Disk usage monitoring for your active connections.",
                target: "#metrics-dashboard",
                position: "top"
            }
        ];

        this.overlay = null;
        this.spotlight = null;
        this.tooltip = null;
    }

    start() {
        this.createUI();
        this.showStep(0);
        document.body.style.overflow = 'hidden';
        const welcome = document.querySelector('.welcome-container');
        if (welcome) welcome.style.overflow = 'hidden';
    }

    createUI() {
        this.overlay = document.createElement('div');
        this.overlay.className = 'onboarding-overlay';

        this.spotlight = document.createElement('div');
        this.spotlight.className = 'onboarding-spotlight';

        this.tooltip = document.createElement('div');
        this.tooltip.className = 'onboarding-tooltip';

        document.body.appendChild(this.overlay);
        document.body.appendChild(this.spotlight);
        document.body.appendChild(this.tooltip);
    }

    showStep(index) {
        this.currentStep = index;
        const step = this.steps[index];
        const targetEl = document.querySelector(step.target);

        if (!targetEl && step.position !== 'center') {
            this.next();
            return;
        }

        // Update Tooltip Content
        this.tooltip.innerHTML = `
            <div class="onboarding-header">
                <div class="brand-logo-container onboarding">
                    <svg viewBox="0 0 100 100" class="owl-svg">
                        <path d="M50 15 L85 35 L85 75 L50 95 L15 75 L15 35 Z" class="owl-shield" />
                        <path d="M30 45 L45 60 M70 45 L55 60" class="owl-eyes-sharp" />
                    </svg>
                </div>
                <div class="onboarding-title-wrap">
                    <h4>${step.title}</h4>
                </div>
            </div>
            <p>${step.text}</p>
            <div class="onboarding-actions">
                <div class="onboarding-dots">
                    ${this.steps.map((_, i) => `<div class="onboarding-dot ${i === index ? 'active' : ''}"></div>`).join('')}
                </div>
                <div class="onboarding-btn-group">
                    <button class="onboarding-btn skip-btn">Skip</button>
                    <button class="onboarding-btn primary next-btn">${index === this.steps.length - 1 ? 'Finish' : 'Next'}</button>
                </div>
            </div>
        `;

        // Event Listeners
        this.tooltip.querySelector('.skip-btn').onclick = () => this.finish();
        this.tooltip.querySelector('.next-btn').onclick = () => this.next();

        // Position Spotlight and Tooltip
        this.positionUI(targetEl, step.position);
    }

    positionUI(targetEl, position) {
        if (position === 'center') {
            this.spotlight.style.opacity = '0';
            this.tooltip.style.top = '50%';
            this.tooltip.style.left = '50%';
            this.tooltip.style.transform = 'translate(-50%, -50%)';
            return;
        }

        this.spotlight.style.opacity = '1';
        const rect = targetEl.getBoundingClientRect();
        const padding = 5;

        this.spotlight.style.top = `${rect.top - padding}px`;
        this.spotlight.style.left = `${rect.left - padding}px`;
        this.spotlight.style.width = `${rect.width + padding * 2}px`;
        this.spotlight.style.height = `${rect.height + padding * 2}px`;

        // Tooltip positioning with safety checks
        let top, left, transform = 'none';
        const tooltipWidth = 340;
        const tooltipHeight = 220;
        const margin = 20;

        if (position === 'right') {
            top = rect.top + rect.height / 2;
            left = rect.right + margin;
            transform = 'translateY(-50%)';

            // Check if off-screen right
            if (left + tooltipWidth > window.innerWidth - margin) {
                left = rect.left - tooltipWidth - margin;
            }
        } else if (position === 'top') {
            top = rect.top - margin;
            left = rect.left + rect.width / 2;
            transform = 'translate(-50%, -100%)';

            // Check if off-screen top
            if (top - tooltipHeight < margin) {
                top = rect.bottom + margin;
                transform = 'translateX(-50%)';
            }
        } else if (position === 'bottom') {
            top = rect.bottom + margin;
            left = rect.left + rect.width / 2;
            transform = 'translateX(-50%)';

            // Check if off-screen bottom
            if (top + tooltipHeight > window.innerHeight - margin) {
                top = rect.top - margin;
                transform = 'translate(-50%, -100%)';
            }
        }

        // Final safety clamp for X
        let finalLeft = left;
        if (transform.includes('-50%') || transform.includes('translateX')) {
            finalLeft = Math.max(tooltipWidth / 2 + margin, Math.min(left, window.innerWidth - tooltipWidth / 2 - margin));
        } else {
            finalLeft = Math.max(margin, Math.min(left, window.innerWidth - tooltipWidth - margin));
        }

        // Final safety clamp for Y
        let finalTop = top;
        if (transform.includes('-100%')) {
            finalTop = Math.max(tooltipHeight + margin, top);
        } else if (transform.includes('-50%') || transform.includes('translateY')) {
            finalTop = Math.max(tooltipHeight / 2 + margin, Math.min(top, window.innerHeight - tooltipHeight / 2 - margin));
        } else {
            finalTop = Math.max(margin, Math.min(top, window.innerHeight - tooltipHeight - margin));
        }

        this.tooltip.style.top = `${finalTop}px`;
        this.tooltip.style.left = `${finalLeft}px`;
        this.tooltip.style.transform = transform;
    }

    next() {
        if (this.currentStep < this.steps.length - 1) {
            this.showStep(this.currentStep + 1);
        } else {
            this.finish();
        }
    }

    finish() {
        this.overlay.classList.add('hidden');
        this.spotlight.style.opacity = '0';
        this.tooltip.style.opacity = '0';
        this.tooltip.style.transform += ' scale(0.9)';

        setTimeout(() => {
            this.overlay.remove();
            this.spotlight.remove();
            this.tooltip.remove();
            localStorage.setItem('onboarding_completed', 'true');
            document.body.style.overflow = '';
            const welcome = document.querySelector('.welcome-container');
            if (welcome) welcome.style.overflow = 'auto';

            // Show preferences popup after onboarding completes (first run only)
            if (!localStorage.getItem('owl_first_use_logging')) {
                setTimeout(() => {
                    settingsModal.classList.remove('hidden');
                    localStorage.setItem('owl_first_use_logging', 'true');
                }, 500);
            }
        }, 400);
    }
}



async function loadProcesses() {
    if (!activeSessionId) return;
    const session = sessions[activeSessionId];
    processListBody.innerHTML = '<tr><td colspan="6" style="text-align:center">Loading...</td></tr>';
    const processes = await ipcRenderer.invoke('get-processes', { connection: session.connection });
    processListBody.innerHTML = '';
    processes.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${p.pid}</td>
            <td>${p.user}</td>
            <td>${p.cpu}%</td>
            <td>${p.mem}%</td>
            <td title="${p.comm}">${p.comm}</td>
            <td><button class="btn-kill" data-pid="${p.pid}">Kill</button></td>
        `;
        tr.querySelector('.btn-kill').onclick = async () => {
            if (await showConfirm({
                title: 'Kill process?',
                message: `Kill process ${p.pid} (${p.comm})?`,
                confirmText: 'Kill',
                variant: 'danger'
            })) {
                const success = await ipcRenderer.invoke('kill-process', { connection: session.connection, pid: p.pid });
                if (success) loadProcesses();
            }
        };
        processListBody.appendChild(tr);
    });
}

function isDockerCapableConnection(connection) {
    if (!connection || connection.type === 'folder') return false;
    const proto = connection.protocol || 'ssh';
    return proto === 'ssh' || proto === 'local';
}

function setDockerStatus(message, type = 'info', hide = false) {
    if (hide || !message) {
        dockerStatusBanner.classList.add('hidden');
        dockerStatusBanner.textContent = '';
        return;
    }
    dockerStatusBanner.className = `docker-status-banner ${type}`;
    dockerStatusBanner.textContent = message;
    dockerStatusBanner.classList.remove('hidden');
}

function getDockerConnectionLabel(connection) {
    if (!connection) return '';
    if (connection.id === 'local-terminal') return 'Local Terminal';
    const host = connection.host || 'localhost';
    const port = connection.port ? `:${connection.port}` : '';
    return `${connection.label} (${connection.user}@${host}${port})`;
}

function resetDockerViewer() {
    dockerDetailsPanel.classList.add('hidden');
    dockerDetailsPanel.innerHTML = '';
    dockerActionBar.classList.add('hidden');
    dockerActionBar.innerHTML = '';
    dockerViewerTitle.textContent = 'Details & Live Logs';
    dockerClearLogsBtn.classList.add('hidden');
    dockerToggleFollowBtn.classList.add('hidden');
    dockerStopLogsBtn.classList.add('hidden');
    dockerLogsViewer.textContent = '';
    dockerLogsEmpty.classList.remove('hidden');
}

async function stopDockerLogStream() {
    if (dockerLogStreamId) {
        await ipcRenderer.invoke('docker-logs-stream-stop', { streamId: dockerLogStreamId });
        dockerLogStreamId = null;
    }
}

function closeDockerExplorer() {
    stopDockerLogStream();
    ipcRenderer.invoke('docker-logs-stream-stop-all');
    dockerModal.classList.add('hidden');
    dockerSelectedItem = null;
    dockerExplorerConnection = null;
}

async function openDockerExplorer(connection) {
    if (!isDockerCapableConnection(connection)) {
        showNotification('Docker Explorer', 'Docker is only available for SSH and local connections.', 'error');
        return;
    }

    dockerExplorerConnection = connection;
    dockerModalSubtitle.textContent = getDockerConnectionLabel(connection);
    dockerSearch.value = '';
    dockerActiveTab = 'containers';
    dockerSelectedItem = null;
    dockerContainersCache = null;
    dockerImagesCache = null;
    dockerVolumesCache = null;
    dockerTabLoadedAt = {};
    document.querySelectorAll('.docker-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'containers'));
    resetDockerViewer();
    dockerModal.classList.remove('hidden');
    await initializeDockerExplorer();
}

async function initializeDockerExplorer() {
    if (!dockerExplorerConnection) return;

    dockerResourceList.innerHTML = '<div class="docker-empty-state">Checking Docker...</div>';
    setDockerStatus('Checking Docker daemon...', 'info');

    try {
        const available = await ipcRenderer.invoke('docker-check', { connection: dockerExplorerConnection });
        if (!available) {
            setDockerStatus('Docker is not available on this host. Install Docker and ensure your user can run docker commands.', 'error');
            dockerResourceList.innerHTML = '<div class="docker-empty-state">No Docker daemon detected</div>';
            dockerStatsEl.classList.add('hidden');
            return;
        }

        setDockerStatus('', 'info', true);
        await loadDockerStats();
        await loadDockerTab('containers');
    } catch (err) {
        setDockerStatus(`Failed to connect to Docker: ${err.message || err}`, 'error');
        dockerResourceList.innerHTML = '<div class="docker-empty-state">Unable to reach Docker</div>';
    }
}

async function loadDockerStats() {
    const stats = await ipcRenderer.invoke('docker-get-stats', { connection: dockerExplorerConnection });
    dockerStatRunning.textContent = stats.running;
    dockerStatContainers.textContent = stats.total;
    dockerStatImages.textContent = stats.images;
    dockerStatVolumes.textContent = stats.volumes;
    dockerStatsEl.classList.remove('hidden');
}

async function refreshDockerView(force = true) {
    if (!dockerExplorerConnection) return;
    dockerTabLoadedAt[dockerActiveTab] = 0;
    await loadDockerStats();
    await loadDockerTab(dockerActiveTab, force);
    if (dockerSelectedItem) {
        await showDockerSelection(dockerSelectedItem, false);
    }
}

async function loadDockerTab(tab, force = false) {
    if (!dockerExplorerConnection) return;

    const now = Date.now();
    if (!force && dockerTabLoadedAt[tab] && (now - dockerTabLoadedAt[tab]) < DOCKER_CACHE_TTL_MS) {
        renderDockerResourceList();
        return;
    }

    dockerResourceList.innerHTML = '<div class="docker-empty-state"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';

    try {
        if (tab === 'containers') {
            dockerContainersCache = await ipcRenderer.invoke('docker-list-containers', { connection: dockerExplorerConnection });
        } else if (tab === 'images') {
            dockerImagesCache = await ipcRenderer.invoke('docker-list-images', { connection: dockerExplorerConnection });
        } else if (tab === 'volumes') {
            dockerVolumesCache = await ipcRenderer.invoke('docker-list-volumes', { connection: dockerExplorerConnection });
        }
        dockerTabLoadedAt[tab] = now;
        renderDockerResourceList();
    } catch (err) {
        dockerResourceList.innerHTML = `<div class="docker-empty-state">Failed to load ${tab}</div>`;
        setDockerStatus(`Failed to load ${tab}: ${err.message || err}`, 'error');
    }
}

function getDockerCacheForTab(tab) {
    if (tab === 'containers') return dockerContainersCache || [];
    if (tab === 'images') return dockerImagesCache || [];
    if (tab === 'volumes') return dockerVolumesCache || [];
    return [];
}

function renderDockerResourceList() {
    const query = dockerSearch.value.trim().toLowerCase();
    const items = getDockerCacheForTab(dockerActiveTab);
    dockerResourceList.innerHTML = '';

    const filtered = items.filter(item => {
        const haystack = JSON.stringify(item).toLowerCase();
        return !query || haystack.includes(query);
    });

    if (filtered.length === 0) {
        dockerResourceList.innerHTML = `<div class="docker-empty-state">No ${dockerActiveTab} found</div>`;
        return;
    }

    filtered.forEach(item => {
        const el = document.createElement('div');
        el.className = 'docker-resource-item';
        if (dockerSelectedItem && dockerSelectedItem.ref === getDockerItemRef(item, dockerActiveTab)) {
            el.classList.add('active');
        }

        if (dockerActiveTab === 'containers') {
            const isRunning = (item.state || '').toLowerCase().includes('running');
            el.innerHTML = `
                <div class="docker-resource-icon container"><i class="fas fa-box"></i></div>
                <div class="docker-resource-info">
                    <div class="docker-resource-name">${sanitizeHTML(item.name || item.id)}</div>
                    <div class="docker-resource-meta">${sanitizeHTML(item.image)} · ${sanitizeHTML(item.runningFor || item.status)}</div>
                </div>
                <span class="docker-state ${isRunning ? 'running' : 'stopped'}">${isRunning ? 'running' : item.state || 'stopped'}</span>
            `;
        } else if (dockerActiveTab === 'images') {
            el.innerHTML = `
                <div class="docker-resource-icon image"><i class="fas fa-layer-group"></i></div>
                <div class="docker-resource-info">
                    <div class="docker-resource-name">${sanitizeHTML(item.repository)}:${sanitizeHTML(item.tag)}</div>
                    <div class="docker-resource-meta">${sanitizeHTML(item.size)} · ${sanitizeHTML(item.created)}</div>
                </div>
                <span class="docker-resource-id">${sanitizeHTML(item.id.slice(0, 12))}</span>
            `;
        } else {
            el.innerHTML = `
                <div class="docker-resource-icon volume"><i class="fas fa-database"></i></div>
                <div class="docker-resource-info">
                    <div class="docker-resource-name">${sanitizeHTML(item.name)}</div>
                    <div class="docker-resource-meta">Driver: ${sanitizeHTML(item.driver)}</div>
                </div>
            `;
        }

        el.onclick = () => {
            document.querySelectorAll('.docker-resource-item').forEach(n => n.classList.remove('active'));
            el.classList.add('active');
            const selection = {
                type: dockerActiveTab === 'containers' ? 'container' : dockerActiveTab === 'images' ? 'image' : 'volume',
                ref: getDockerItemRef(item, dockerActiveTab),
                data: item
            };
            showDockerSelection(selection);
        };

        dockerResourceList.appendChild(el);
    });
}

function getDockerItemRef(item, tab) {
    if (tab === 'containers') return item.name || item.id;
    if (tab === 'images') return item.id;
    return item.name;
}

function getDockerImageRef(item) {
    if (item.tag && item.tag !== '<none>') return `${item.repository}:${item.tag}`;
    return item.id;
}

async function showDockerSelection(selection, startLogs = true) {
    dockerSelectedItem = selection;
    dockerViewerTitle.textContent = selection.data.name || selection.data.repository || selection.ref;
    renderDockerActionBar(selection);
    await renderDockerDetails(selection);

    if (selection.type === 'container' && startLogs) {
        await startDockerLogStream(selection.ref, selection.data.name || selection.ref);
    } else {
        stopDockerLogStream();
        dockerClearLogsBtn.classList.add('hidden');
        dockerToggleFollowBtn.classList.add('hidden');
        dockerStopLogsBtn.classList.add('hidden');
        dockerLogsViewer.textContent = '';
        dockerLogsEmpty.textContent = selection.type === 'container'
            ? 'Select a container to stream live logs'
            : 'Live logs are available for containers only';
        dockerLogsEmpty.classList.remove('hidden');
    }
}

function renderDockerActionBar(selection) {
    dockerActionBar.innerHTML = '';
    dockerActionBar.classList.remove('hidden');

    const primary = document.createElement('div');
    primary.className = 'docker-action-group';
    const utility = document.createElement('div');
    utility.className = 'docker-action-group';
    const danger = document.createElement('div');
    danger.className = 'docker-action-group docker-action-danger';

    const addAction = (group, label, className, onClick, isDanger = false) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `btn-docker-action ${className}${isDanger ? ' danger' : ''}`;
        btn.textContent = label;
        btn.onclick = onClick;
        group.appendChild(btn);
    };

    if (selection.type === 'container') {
        const state = (selection.data.state || '').toLowerCase();
        const isRunning = state === 'running';
        const isPaused = state === 'paused';
        const ref = selection.ref;

        if (!isRunning && !isPaused) {
            addAction(primary, 'Start', 'start', () => runDockerContainerAction(ref, 'start'));
        } else if (isPaused) {
            addAction(primary, 'Unpause', 'unpause', () => runDockerContainerAction(ref, 'unpause'));
        } else {
            addAction(primary, 'Stop', 'stop', () => runDockerContainerAction(ref, 'stop'));
            addAction(primary, 'Restart', 'restart', () => runDockerContainerAction(ref, 'restart'));
            addAction(primary, 'Pause', 'pause', () => runDockerContainerAction(ref, 'pause'));
            addAction(danger, 'Kill', 'kill', () => runDockerContainerAction(ref, 'kill', true), true);
        }
        addAction(utility, 'Inspect', 'inspect', () => inspectDockerResource('container', ref));
        addAction(danger, 'Remove', 'remove', () => runDockerContainerAction(ref, 'rm', true), true);
    } else if (selection.type === 'image') {
        const ref = getDockerImageRef(selection.data);
        addAction(utility, 'Inspect', 'inspect', () => inspectDockerResource('image', ref));
        addAction(danger, 'Remove', 'remove', () => runDockerImageAction(ref), true);
    } else if (selection.type === 'volume') {
        addAction(utility, 'Inspect', 'inspect', () => inspectDockerResource('volume', selection.ref));
        addAction(danger, 'Remove', 'remove', () => runDockerVolumeAction(selection.ref), true);
    }

    if (primary.children.length) dockerActionBar.appendChild(primary);
    if (utility.children.length) dockerActionBar.appendChild(utility);
    if (danger.children.length) dockerActionBar.appendChild(danger);
}

async function renderDockerDetails(selection) {
    dockerDetailsPanel.classList.remove('hidden');
    dockerDetailsPanel.innerHTML = '<div class="docker-details-loading"><i class="fas fa-spinner fa-spin"></i> Loading details...</div>';

    const item = selection.data;
    let html = '<div class="docker-details-grid">';

    if (selection.type === 'container') {
        const isRunning = (item.state || '').toLowerCase().includes('running');
        html += buildDetailRow('Name', item.name);
        html += buildDetailRow('ID', item.id);
        html += buildDetailRow('Image', item.image);
        html += buildDetailRow('Status', item.status);
        html += buildDetailRow('State', item.state, isRunning ? 'running' : 'stopped');
        html += buildDetailRow('Uptime', item.runningFor || '—');
        html += buildDetailRow('Size', item.size || '—');
        html += buildDetailRow('Ports', item.ports || '—');
    } else if (selection.type === 'image') {
        html += buildDetailRow('Repository', item.repository);
        html += buildDetailRow('Tag', item.tag);
        html += buildDetailRow('ID', item.id);
        html += buildDetailRow('Size', item.size);
        html += buildDetailRow('Created', item.created);
    } else {
        html += buildDetailRow('Name', item.name);
        html += buildDetailRow('Driver', item.driver);
    }

    html += '</div>';
    dockerDetailsPanel.innerHTML = html;
}

function buildDetailRow(label, value, stateClass = '') {
    const valueHtml = stateClass
        ? `<span class="docker-state ${stateClass}">${sanitizeHTML(String(value))}</span>`
        : sanitizeHTML(String(value || '—'));
    return `<div class="docker-detail-row"><span class="docker-detail-label">${label}</span><span class="docker-detail-value">${valueHtml}</span></div>`;
}

async function inspectDockerResource(resourceType, resourceRef) {
    const result = await ipcRenderer.invoke('docker-inspect', {
        connection: dockerExplorerConnection,
        resourceType,
        resourceRef
    });

    if (!result.success) {
        showNotification('Inspect Failed', result.error || 'Could not inspect resource.', 'error');
        return;
    }

    dockerDetailsPanel.innerHTML = `
        <div class="docker-inspect-header">
            <span><i class="fas fa-code"></i> Inspect — ${sanitizeHTML(resourceRef)}</span>
            <button type="button" class="btn-docker-action" id="docker-inspect-back">Back to summary</button>
        </div>
        <pre class="docker-inspect-json">${sanitizeHTML(JSON.stringify(result.data, null, 2))}</pre>
    `;
    document.getElementById('docker-inspect-back').onclick = () => {
        if (dockerSelectedItem) renderDockerDetails(dockerSelectedItem);
    };
}

async function runDockerContainerAction(containerRef, action, needsConfirm = false) {
    if (!dockerExplorerConnection) return;
    const labels = { start: 'Start', stop: 'Stop', restart: 'Restart', rm: 'Remove', kill: 'Kill', pause: 'Pause', unpause: 'Unpause' };
    if (needsConfirm && !await showConfirm({
        title: `${labels[action] || action} container?`,
        message: `${labels[action] || action} container "${containerRef}"?`,
        confirmText: labels[action] || 'Confirm',
        variant: action === 'rm' || action === 'kill' ? 'danger' : 'primary'
    })) return;

    const result = await ipcRenderer.invoke('docker-container-action', {
        connection: dockerExplorerConnection,
        containerRef,
        action
    });

    if (result.success) {
        showNotification('Docker', `Container ${labels[action] || action} successful.`, 'success');
        dockerTabLoadedAt.containers = 0;
        await loadDockerStats();
        await loadDockerTab('containers', true);
        if (dockerSelectedItem && dockerSelectedItem.ref === containerRef) {
            const updated = (dockerContainersCache || []).find(c => (c.name || c.id) === containerRef);
            if (updated) {
                dockerSelectedItem.data = updated;
                await showDockerSelection(dockerSelectedItem, action !== 'rm');
            } else if (action === 'rm') {
                dockerSelectedItem = null;
                resetDockerViewer();
            }
        }
    } else {
        showNotification('Docker Error', result.error || 'Action failed.', 'error');
    }
}

async function runDockerImageAction(imageRef) {
    if (!await showConfirm({
        title: 'Remove image?',
        message: `Remove image "${imageRef}"?`,
        confirmText: 'Remove',
        variant: 'danger'
    })) return;
    const result = await ipcRenderer.invoke('docker-image-action', {
        connection: dockerExplorerConnection,
        imageRef,
        action: 'rm'
    });
    if (result.success) {
        showNotification('Docker', 'Image removed successfully.', 'success');
        dockerTabLoadedAt.images = 0;
        await loadDockerStats();
        await loadDockerTab('images', true);
        dockerSelectedItem = null;
        resetDockerViewer();
    } else {
        showNotification('Docker Error', result.error || 'Failed to remove image.', 'error');
    }
}

async function runDockerVolumeAction(volumeName) {
    if (!await showConfirm({
        title: 'Remove volume?',
        message: `Remove volume "${volumeName}"?`,
        confirmText: 'Remove',
        variant: 'danger'
    })) return;
    const result = await ipcRenderer.invoke('docker-volume-action', {
        connection: dockerExplorerConnection,
        volumeName,
        action: 'rm'
    });
    if (result.success) {
        showNotification('Docker', 'Volume removed successfully.', 'success');
        dockerTabLoadedAt.volumes = 0;
        await loadDockerStats();
        await loadDockerTab('volumes', true);
        dockerSelectedItem = null;
        resetDockerViewer();
    } else {
        showNotification('Docker Error', result.error || 'Failed to remove volume.', 'error');
    }
}

async function startDockerLogStream(containerRef, displayName) {
    await stopDockerLogStream();
    dockerLogsViewer.textContent = '';
    dockerLogsEmpty.classList.add('hidden');
    dockerClearLogsBtn.classList.remove('hidden');
    dockerToggleFollowBtn.classList.remove('hidden');
    dockerStopLogsBtn.classList.remove('hidden');
    dockerViewerTitle.textContent = `Live logs — ${displayName}`;

    const result = await ipcRenderer.invoke('docker-logs-stream-start', {
        connection: dockerExplorerConnection,
        containerRef,
        tail: 200
    });

    if (result.success) {
        dockerLogStreamId = result.streamId;
    } else {
        dockerLogsViewer.textContent = result.error || 'Failed to start log stream.';
        showNotification('Docker Logs', result.error || 'Failed to start stream.', 'error');
    }
}

async function loadSageConfig() {
    try {
        const loaded = await ipcRenderer.invoke('load-sage-config');
        if (loaded) {
            sageConfig = { ...sageConfig, ...loaded };
            sageConfig.provider = normalizeSageProvider(sageConfig.provider);
        }
    } catch (err) {
        console.error('Failed to load Sage config:', err);
    }
    updateSagePanelState();
}

function isSageConfigured() {
    if (!sageConfig.enabled || !sageConfig.apiKey) return false;
    const meta = getSageProviderMeta(sageConfig.provider);
    if (meta.requiresBaseUrl && !(sageConfig.baseUrl || '').trim()) return false;
    return true;
}

function updateSagePanelState() {
    if (!sageNotConfigured || !sagePanelBody) return;
    const configured = isSageConfigured();
    sageNotConfigured.classList.toggle('hidden', configured);
    sagePanelBody.classList.toggle('hidden', !configured);
}

function getActiveSessionConnection() {
    if (!activeSessionId || !sessions[activeSessionId]) return null;
    return sessions[activeSessionId].connection;
}

function getConnectionContextHeader(connection) {
    if (!connection) return 'No active session';
    if (connection.id === 'local-terminal') return 'Local Terminal';
    const host = connection.host || 'localhost';
    const port = connection.port ? `:${connection.port}` : '';
    return `${connection.label} · ${connection.user}@${host}${port}`;
}

function toggleSagePanel(forceOpen = false) {
    if (!sagePanel) return;
    const shouldOpen = forceOpen || sagePanel.classList.contains('hidden');
    if (shouldOpen) {
        openSagePanel();
    } else {
        closeSagePanel();
    }
}

function openSagePanel() {
    if (!sagePanel) return;
    sagePanel.classList.remove('hidden');
    document.body.classList.add('sage-panel-open');
    updateSagePanelState();
    const connection = getActiveSessionConnection();
    if (sageConnectionBadge) {
        sageConnectionBadge.textContent = getConnectionContextHeader(connection);
    }
    if (toggleSageBtn) toggleSageBtn.classList.add('active');
    if (sageInput) sageInput.focus();
}

function closeSagePanel() {
    if (!sagePanel) return;
    sagePanel.classList.add('hidden');
    document.body.classList.remove('sage-panel-open');
    if (toggleSageBtn) toggleSageBtn.classList.remove('active');
}

function clearSageChat() {
    sageChatHistory = [];
    sagePendingContext = '';
    if (sageContextPreview) {
        sageContextPreview.classList.add('hidden');
        sageContextPreview.textContent = '';
    }
    if (sageMessages) {
        sageMessages.innerHTML = `
            <div class="sage-welcome">
                <p>Ask Sage to explain errors, suggest commands, or diagnose your server.</p>
                <p class="sage-welcome-hint">Use <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>I</kbd> to open anytime.</p>
            </div>
        `;
    }
}

function setSageContextPreview(text) {
    if (!sageContextPreview) return;
    if (!text || !text.trim()) {
        sageContextPreview.classList.add('hidden');
        sageContextPreview.textContent = '';
        return;
    }
    const preview = text.length > 280 ? `${text.slice(0, 280)}…` : text;
    sageContextPreview.textContent = preview;
    sageContextPreview.classList.remove('hidden');
}

function attachSageSelection() {
    if (!activeSessionId || !sessions[activeSessionId]) {
        showNotification('OWL Sage', 'No active terminal session.', 'error');
        return;
    }
    const selection = sessions[activeSessionId].term.getSelection();
    if (!selection || !selection.trim()) {
        showNotification('OWL Sage', 'Select text in the terminal first.', 'info');
        return;
    }
    sagePendingContext = `Terminal selection:\n${selection}`;
    setSageContextPreview(sagePendingContext);
    showNotification('OWL Sage', 'Selection attached to next message.', 'success');
}

function attachSageTerminalContext() {
    if (!activeSessionId || !sessions[activeSessionId]) {
        showNotification('OWL Sage', 'No active terminal session.', 'error');
        return;
    }
    const recent = sessions[activeSessionId].term.getRecentLines
        ? sessions[activeSessionId].term.getRecentLines(100)
        : '';
    if (!recent || !recent.trim()) {
        showNotification('OWL Sage', 'Terminal buffer is empty.', 'info');
        return;
    }
    sagePendingContext = `Recent terminal output (last 100 lines):\n${recent}`;
    setSageContextPreview(sagePendingContext);
    showNotification('OWL Sage', 'Terminal context attached.', 'success');
}

async function attachSageDiagnoseContext() {
    const connection = getActiveSessionConnection();
    if (!connection) {
        showNotification('OWL Sage', 'No active session to diagnose.', 'error');
        return;
    }

    if (sageBtnDiagnose) {
        sageBtnDiagnose.disabled = true;
        sageBtnDiagnose.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Diagnosing';
    }

    try {
        sagePendingContext = await buildSageDiagnoseContext(connection);
        setSageContextPreview(sagePendingContext);
        showNotification('OWL Sage', 'Diagnose snapshot attached.', 'success');
    } catch (err) {
        showNotification('OWL Sage', `Diagnose failed: ${err.message || err}`, 'error');
    } finally {
        if (sageBtnDiagnose) {
            sageBtnDiagnose.disabled = false;
            sageBtnDiagnose.innerHTML = '<i class="fas fa-stethoscope"></i> Diagnose';
        }
    }
}

async function buildSageDiagnoseContext(connection) {
    const parts = [`Connection: ${getConnectionContextHeader(connection)}`];

    try {
        const metrics = await ipcRenderer.invoke('get-metrics', { connection });
        parts.push([
            `OS: ${metrics.os}`,
            `Uptime: ${metrics.uptime}`,
            `CPU: ${metrics.cpu.toFixed(1)}%`,
            `RAM: ${metrics.ram.toFixed(1)}%`,
            `Disk: ${metrics.disk}%`
        ].join('\n'));
    } catch (err) {
        parts.push(`Metrics unavailable: ${err.message || err}`);
    }

    try {
        const processes = await ipcRenderer.invoke('get-processes', { connection });
        const top = processes.slice(0, 12).map(p =>
            `${p.pid}\t${p.user}\t${p.cpu}%\t${p.mem}%\t${p.comm}`
        ).join('\n');
        parts.push(`Top processes (PID USER CPU MEM COMMAND):\n${top}`);
    } catch (err) {
        parts.push(`Process list unavailable: ${err.message || err}`);
    }

    if (isDockerCapableConnection(connection)) {
        try {
            const available = await ipcRenderer.invoke('docker-check', { connection });
            if (available) {
                const stats = await ipcRenderer.invoke('docker-get-stats', { connection });
                const containers = await ipcRenderer.invoke('docker-list-containers', { connection });
                parts.push(`Docker: ${stats.running} running / ${stats.total} total containers, ${stats.images} images`);
                const lines = containers.slice(0, 15).map(c =>
                    `${c.name || c.id}\t${c.state}\t${c.image}\t${c.status || ''}`
                ).join('\n');
                if (lines) parts.push(`Containers:\n${lines}`);
            } else {
                parts.push('Docker: not available on this host');
            }
        } catch (err) {
            parts.push(`Docker info unavailable: ${err.message || err}`);
        }
    }

    if (activeSessionId && sessions[activeSessionId]?.term?.getRecentLines) {
        const recent = sessions[activeSessionId].term.getRecentLines(40);
        if (recent && recent.trim()) {
            parts.push(`Recent terminal output:\n${recent}`);
        }
    }

    return parts.join('\n\n');
}

function renderSageMessage(role, content, isStreaming = false) {
    const welcome = sageMessages.querySelector('.sage-welcome');
    if (welcome) welcome.remove();

    const el = document.createElement('div');
    el.className = `sage-message sage-message-${role}${isStreaming ? ' streaming' : ''}`;
    el.innerHTML = formatSageContent(content);
    sageMessages.appendChild(el);
    sageMessages.scrollTop = sageMessages.scrollHeight;
    return el;
}

function formatSageContent(content) {
    if (!content) return '';
    const parts = [];
    const codeRegex = /```(\w*)\n([\s\S]*?)```/g;
    let lastIndex = 0;
    let match;

    while ((match = codeRegex.exec(content)) !== null) {
        const before = content.slice(lastIndex, match.index);
        if (before) {
            parts.push(sanitizeHTML(before).replace(/\n/g, '<br>'));
        }
        const code = match[2].trim();
        parts.push(`<div class="sage-code-block"><pre><code>${sanitizeHTML(code)}</code></pre>
            <div class="sage-code-actions">
                <button type="button" class="sage-code-btn copy">Copy</button>
                <button type="button" class="sage-code-btn run">Run</button>
            </div></div>`);
        lastIndex = codeRegex.lastIndex;
    }

    const tail = content.slice(lastIndex);
    if (tail) {
        parts.push(sanitizeHTML(tail).replace(/\n/g, '<br>'));
    }

    return parts.join('');
}

function bindSageCodeActions(container) {
    container.querySelectorAll('.sage-code-block').forEach(block => {
        const codeEl = block.querySelector('code');
        const cmd = codeEl ? codeEl.textContent : '';
        const copyBtn = block.querySelector('.sage-code-btn.copy');
        const runBtn = block.querySelector('.sage-code-btn.run');
        if (copyBtn) {
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(cmd);
                showNotification('OWL Sage', 'Command copied.', 'success', 2000);
            };
        }
        if (runBtn) {
            runBtn.onclick = async () => {
                if (!cmd) return;
                if (!await showConfirm({
                    title: 'Run command?',
                    message: `Run this command in the active terminal?\n\n${cmd}`,
                    confirmText: 'Run',
                    variant: 'primary'
                })) return;
                runSageCommand(cmd);
            };
        }
    });
}

function runSageCommand(command) {
    if (!activeSessionId || !sessions[activeSessionId]?.pid) {
        showNotification('OWL Sage', 'No active terminal to run command.', 'error');
        return;
    }
    const data = command.endsWith('\n') ? command : `${command}\n`;
    ipcRenderer.send('terminal-write', { pid: sessions[activeSessionId].pid, data });
    showNotification('OWL Sage', 'Command sent to terminal.', 'success', 2000);
}

async function sendSageMessage() {
    if (!isSageConfigured()) {
        showNotification('OWL Sage', 'Configure an AI provider in Settings first.', 'error');
        return;
    }
    if (sageIsStreaming) return;

    const text = sageInput.value.trim();
    if (!text) return;

    sageInput.value = '';
    renderSageMessage('user', text);
    sageChatHistory.push({ role: 'user', content: text });

    const contextParts = [];
    if (sagePendingContext) {
        contextParts.push(sagePendingContext);
        sagePendingContext = '';
        setSageContextPreview('');
    } else if (sageChatHistory.length === 1) {
        const connection = getActiveSessionConnection();
        if (connection) {
            contextParts.push(`Active connection: ${getConnectionContextHeader(connection)}`);
        }
    }

    const assistantEl = renderSageMessage('assistant', '', true);
    sageIsStreaming = true;
    if (sageStopBtn) sageStopBtn.classList.remove('hidden');
    if (sageSendBtn) sageSendBtn.disabled = true;

    const result = await ipcRenderer.invoke('sage-chat-stream-start', {
        messages: sageChatHistory,
        context: contextParts.join('\n\n')
    });

    if (!result.success) {
        finishSageStream(result.error);
        assistantEl.remove();
        return;
    }

    sageStreamId = result.streamId;
    assistantEl.dataset.streamId = result.streamId;
}

function appendSageStreamChunk(chunk) {
    const streamingEl = sageMessages.querySelector('.sage-message-assistant.streaming');
    if (!streamingEl) return;

    const currentText = streamingEl.dataset.rawText || '';
    const nextText = currentText + chunk;
    streamingEl.dataset.rawText = nextText;
    streamingEl.innerHTML = formatSageContent(nextText);
    bindSageCodeActions(streamingEl);
    sageMessages.scrollTop = sageMessages.scrollHeight;
}

function finishSageStream(error = null) {
    const streamingEl = sageMessages.querySelector('.sage-message-assistant.streaming');
    if (streamingEl) {
        streamingEl.classList.remove('streaming');
        const content = error
            ? `Error: ${error}`
            : (streamingEl.dataset.rawText || '');
        if (error) {
            streamingEl.innerHTML = `<span class="sage-error">${sanitizeHTML(error)}</span>`;
        } else {
            streamingEl.innerHTML = formatSageContent(content);
            bindSageCodeActions(streamingEl);
            sageChatHistory.push({ role: 'assistant', content });
        }
    }

    sageStreamId = null;
    sageIsStreaming = false;
    if (sageStopBtn) sageStopBtn.classList.add('hidden');
    if (sageSendBtn) sageSendBtn.disabled = false;
}

async function stopSageStream() {
    if (sageStreamId) {
        await ipcRenderer.invoke('sage-chat-stream-stop', { streamId: sageStreamId });
    }
    finishSageStream('Generation stopped.');
}

function fitActiveTerminal() {
    if (activeSessionId && sessions[activeSessionId]) {
        const session = sessions[activeSessionId];
        if (session.fitAddon) {
            session.fitAddon.fit();
        }
    }
}


// Resizable Sidebar
const sidebar = document.getElementById('sidebar');
const resizeHandle = document.querySelector('.resize-handle');

let isResizing = false;

resizeHandle.addEventListener('mousedown', (e) => {
    isResizing = true;
    resizeHandle.classList.add('resizing');
    document.body.style.cursor = 'ew-resize';
    document.body.style.userSelect = 'none';
});

document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;

    const newWidth = e.clientX;
    const minWidth = 300;
    const maxWidth = 500;

    if (newWidth >= minWidth && newWidth <= maxWidth) {
        sidebar.style.width = newWidth + 'px';
        // Fit terminal when sidebar is resized
        fitActiveTerminal();
    }
});

document.addEventListener('mouseup', () => {
    if (isResizing) {
        isResizing = false;
        resizeHandle.classList.remove('resizing');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        // Final fit after resize is complete
        fitActiveTerminal();
    }
});

// Auto-resize terminal on container resize
const terminalResizeObserver = new ResizeObserver(() => {
    fitActiveTerminal();
});
terminalResizeObserver.observe(terminalsWrapper);

async function loadLogs() {
    let logs = await ipcRenderer.invoke('list-logs');
    const query = logFileSearch.value.toLowerCase();
    const timeframe = logTimeframeFilter.value;

    // Filter by name
    if (query) {
        logs = logs.filter(l => l.name.toLowerCase().includes(query));
    }

    // Filter by timeframe
    const now = new Date();
    if (timeframe === 'today') {
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        logs = logs.filter(l => new Date(l.mtime) >= today);
    } else if (timeframe === 'week') {
        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        logs = logs.filter(l => new Date(l.mtime) >= weekAgo);
    } else if (timeframe === 'month') {
        const monthAgo = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
        logs = logs.filter(l => new Date(l.mtime) >= monthAgo);
    } else if (timeframe === 'custom') {
        const start = logStartDate.value ? new Date(logStartDate.value) : null;
        const end = logEndDate.value ? new Date(logEndDate.value) : null;
        if (end) end.setHours(23, 59, 59, 999);

        logs = logs.filter(l => {
            const mtime = new Date(l.mtime);
            if (start && mtime < start) return false;
            if (end && mtime > end) return false;
            return true;
        });
    }

    logsList.innerHTML = '';
    selectAllLogs.checked = false;
    deleteSelectedLogsBtn.classList.add('hidden');

    if (logs.length === 0) {
        logsList.innerHTML = '<div class="log-empty-state">No logs found</div>';
        return;
    }

    // Sort by mtime descending
    logs.sort((a, b) => new Date(b.mtime) - new Date(a.mtime));

    logs.forEach(log => {
        const item = document.createElement('div');
        item.className = 'log-item';
        if (selectedLogFile === log.name) item.classList.add('active');

        const date = new Date(log.mtime).toLocaleString();
        const size = formatSize(log.size);

        item.innerHTML = `
            <label class="checkbox-container">
                <input type="checkbox" class="log-checkbox" data-filename="${sanitizeHTML(log.name)}">
                <span class="checkmark"></span>
            </label>
            <div class="log-item-content">
                <div class="log-item-name">${sanitizeHTML(log.name)}</div>
                <div class="log-item-meta">
                    <span>${sanitizeHTML(date)}</span>
                    <span>${sanitizeHTML(size)}</span>
                </div>
            </div>
        `;

        item.onclick = (e) => {
            if (e.target.closest('.checkbox-container')) return;
            document.querySelectorAll('.log-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            viewLog(log.name);
        };

        const checkbox = item.querySelector('.log-checkbox');
        checkbox.onchange = () => {
            updateDeleteSelectedBtnVisibility();
        };

        item.querySelector('.checkbox-container').onclick = (e) => e.stopPropagation();

        logsList.appendChild(item);
    });
}

function updateDeleteSelectedBtnVisibility() {
    const selectedCount = document.querySelectorAll('.log-checkbox:checked').length;
    if (selectedCount > 0) {
        deleteSelectedLogsBtn.classList.remove('hidden');
        deleteSelectedLogsBtn.innerHTML = `<i class="fas fa-trash"></i> Delete (${selectedCount})`;
    } else {
        deleteSelectedLogsBtn.classList.add('hidden');
    }
}

async function viewLog(filename) {
    selectedLogFile = filename;
    logContent.innerHTML = '<div class="log-empty-state">Loading...</div>';
    logContentSearch.value = '';

    const content = await ipcRenderer.invoke('read-log', filename);
    if (content !== null) {
        currentLogRawContent = content;
        renderLogContent(content);
    } else {
        logContent.innerHTML = '<div class="log-empty-state text-danger">Failed to load log</div>';
    }
}

function renderLogContent(content) {
    // Basic ANSI to HTML conversion (colors only)
    let html = content
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\u001b\[30m/g, '<span style="color: #000">')
        .replace(/\u001b\[31m/g, '<span style="color: #ff5555">')
        .replace(/\u001b\[32m/g, '<span style="color: #50fa7b">')
        .replace(/\u001b\[33m/g, '<span style="color: #f1fa8c">')
        .replace(/\u001b\[34m/g, '<span style="color: #bd93f9">')
        .replace(/\u001b\[35m/g, '<span style="color: #ff79c6">')
        .replace(/\u001b\[36m/g, '<span style="color: #8be9fd">')
        .replace(/\u001b\[37m/g, '<span style="color: #f8f8f2">')
        .replace(/\u001b\[0m/g, '</span>')
        // Remove other ANSI codes
        .replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

    logContent.innerHTML = html;
    logContent.scrollTop = logContent.scrollHeight;
}

function performLogSearch() {
    const query = logContentSearch.value.trim();
    if (!query) {
        renderLogContent(currentLogRawContent);
        logSearchCount.innerText = '0/0';
        logSearchMatches = [];
        currentLogSearchIndex = -1;
        return;
    }

    // Clean ANSI for search
    let cleanContent = currentLogRawContent.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

    // Escape regex chars
    const escapedQuery = query.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    const regex = new RegExp(escapedQuery, 'gi');

    // Find all matches
    logSearchMatches = [];
    let match;
    while ((match = regex.exec(cleanContent)) !== null) {
        logSearchMatches.push(match.index);
    }

    if (logSearchMatches.length > 0) {
        currentLogSearchIndex = 0;
        highlightAndScrollToMatch();
    } else {
        currentLogSearchIndex = -1;
        renderLogContent(currentLogRawContent);
        logSearchCount.innerText = '0/0';
    }
}

function highlightAndScrollToMatch() {
    const query = logContentSearch.value.trim();
    const escapedQuery = query.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    const regex = new RegExp(`(${escapedQuery})`, 'gi');

    let cleanContent = currentLogRawContent.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

    let matchCounter = 0;
    let html = cleanContent
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(regex, (match) => {
            const isCurrent = matchCounter === currentLogSearchIndex;
            matchCounter++;
            return `<mark id="log-match-${matchCounter - 1}" class="${isCurrent ? 'current-match' : ''}">${match}</mark>`;
        });

    logContent.innerHTML = html;
    logSearchCount.innerText = `${currentLogSearchIndex + 1}/${logSearchMatches.length}`;

    // Scroll to current match
    const currentEl = document.getElementById(`log-match-${currentLogSearchIndex}`);
    if (currentEl) {
        currentEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function navigateLogSearch(direction) {
    if (logSearchMatches.length === 0) return;

    currentLogSearchIndex += direction;
    if (currentLogSearchIndex >= logSearchMatches.length) currentLogSearchIndex = 0;
    if (currentLogSearchIndex < 0) currentLogSearchIndex = logSearchMatches.length - 1;

    highlightAndScrollToMatch();
}
// Global Modal Closing Logic
window.addEventListener('click', (event) => {
    if (event.target.classList.contains('modal')) {
        // Don't close vault modals by clicking outside
        if (event.target.id === 'vault-unlock-modal' || event.target.id === 'vault-setup-modal') {
            return;
        }
        event.target.classList.add('hidden');
    }
});

// --- New Modal Logic ---

function updateBastionStatusDot() {
    const host = document.getElementById('bastion-host').value;
    const dot = document.getElementById('bastion-status-dot');
    if (dot) {
        if (host && host.trim() !== '') {
            dot.classList.remove('hidden');
        } else {
            dot.classList.add('hidden');
        }
    }
}

// Bastion Host Input Listener
const bastionHostInput = document.getElementById('bastion-host');
if (bastionHostInput) {
    bastionHostInput.addEventListener('input', updateBastionStatusDot);
}

// Bastion Key Browse
const browseBastionKeyBtn = document.getElementById('browse-bastion-key-btn');
const bastionKeyPathInput = document.getElementById('bastion-key-path');

if (browseBastionKeyBtn) {
    browseBastionKeyBtn.onclick = async () => {
        const filePath = await ipcRenderer.invoke('open-file-dialog', {
            title: 'Select Bastion Private Key',
            filters: [
                { name: 'All Files', extensions: ['*'] },
                { name: 'Keys', extensions: ['key', 'pem', 'id_rsa', 'id_ed25519'] }
            ]
        });
        if (filePath) {
            bastionKeyPathInput.value = filePath;
        }
    };
}

// Tab Switching Logic
const segmentBtns = document.querySelectorAll('.segment-btn');
const tabContents = document.querySelectorAll('.tab-content');

segmentBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        // Remove active class from all buttons and contents
        segmentBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => {
            c.classList.remove('active');
            c.classList.add('hidden');
        });

        // Add active class to clicked button
        btn.classList.add('active');

        // Show corresponding tab content
        const tabId = btn.dataset.tab;
        const targetTab = document.getElementById(tabId);
        if (targetTab) {
            targetTab.classList.remove('hidden');
            targetTab.classList.add('active');
        }
    });
});

// --- Protocol Logic ---

function updateProtocolFields() {
    const protocol = currentProtocol;
    const protocolOptions = document.querySelectorAll('.protocol-option');

    // Update active state
    protocolOptions.forEach(opt => {
        if (opt.dataset.value === protocol) {
            opt.classList.add('active');
        } else {
            opt.classList.remove('active');
        }
    });

    // Adjust fields based on protocol
    const portInput = document.getElementById('port');
    const keyAuthOption = document.querySelector('.auth-option[data-value="key"]');
    const sshOptionsGroup = document.getElementById('ssh-options-group');
    const isFolder = connectionForm?.dataset?.type === 'folder';

    if (protocol === 'ssh') {
        if (portInput.value === '3389' || portInput.value === '5900') portInput.value = '22';
        if (keyAuthOption) keyAuthOption.style.display = 'flex';
        if (sshOptionsGroup) sshOptionsGroup.style.display = isFolder ? 'none' : 'block';
    } else if (protocol === 'rdp') {
        if (portInput.value === '22' || portInput.value === '5900') portInput.value = '3389';
        if (keyAuthOption) keyAuthOption.style.display = 'none';
        if (sshOptionsGroup) sshOptionsGroup.style.display = 'none';
        // Force password auth if switching to RDP
        if (currentAuthType === 'key') {
            document.querySelector('.auth-option[data-value="password"]').click();
        }
    } else if (protocol === 'vnc') {
        if (portInput.value === '22' || portInput.value === '3389') portInput.value = '5900';
        if (keyAuthOption) keyAuthOption.style.display = 'none';
        if (sshOptionsGroup) sshOptionsGroup.style.display = 'none';
        if (currentAuthType === 'key') {
            document.querySelector('.auth-option[data-value="password"]').click();
        }
    }
}

// Protocol Option Click Listeners
document.querySelectorAll('.protocol-option').forEach(opt => {
    opt.addEventListener('click', () => {
        currentProtocol = opt.dataset.value;
        updateProtocolFields();
    });
});

// --- Advanced SSH Options ---

function isValidSshOptionKey(key) {
    return /^[A-Za-z][A-Za-z0-9]*$/.test(key || '');
}

function isValidSshOptionValue(value) {
    return typeof value === 'string' && value.length > 0 && value.length < 256 && !/[\r\n\0]/.test(value);
}

function createDefaultSshOptionsDraft() {
    return SSH_OPTION_PRESETS.map((preset) => ({
        id: `preset:${preset.key}`,
        key: preset.key,
        value: preset.value,
        description: preset.description,
        enabled: false,
        preset: true
    }));
}

function loadSshOptionsDraft(savedOptions = []) {
    const draft = createDefaultSshOptionsDraft();
    const saved = Array.isArray(savedOptions) ? savedOptions : [];

    for (const savedOpt of saved) {
        if (!savedOpt || !savedOpt.key) continue;
        const key = String(savedOpt.key).trim();
        const value = String(savedOpt.value ?? '').trim();
        const enabled = !!savedOpt.enabled;
        const presetIdx = draft.findIndex(opt => opt.key === key);

        if (presetIdx >= 0) {
            draft[presetIdx] = {
                ...draft[presetIdx],
                value: value || draft[presetIdx].value,
                enabled
            };
        } else if (isValidSshOptionKey(key)) {
            draft.push({
                id: savedOpt.id || `custom:${key}:${generateId()}`,
                key,
                value,
                description: 'Custom OpenSSH option',
                enabled,
                preset: false
            });
        }
    }

    sshOptionsDraft = draft;
    setSshAdvExpanded(false);
    renderSshOptionsList();
    updateSshAdvCount();
}

function getSshOptionsForSave() {
    return sshOptionsDraft
        .filter(opt => opt.preset || opt.enabled || (opt.value && opt.value.trim()))
        .map(opt => ({
            id: opt.id,
            key: opt.key,
            value: String(opt.value ?? '').trim(),
            enabled: !!opt.enabled,
            preset: !!opt.preset
        }))
        .filter(opt => isValidSshOptionKey(opt.key));
}

function setSshAdvExpanded(expanded) {
    const root = document.getElementById('ssh-adv');
    const body = document.getElementById('ssh-adv-body');
    const toggle = document.getElementById('ssh-adv-toggle');
    if (!root || !body || !toggle) return;
    root.classList.toggle('is-open', expanded);
    body.classList.toggle('hidden', !expanded);
    toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
}

function updateSshAdvCount() {
    const countEl = document.getElementById('ssh-adv-count');
    if (!countEl) return;
    const active = sshOptionsDraft.filter(opt => opt.enabled).length;
    countEl.textContent = active === 1 ? '1 active' : `${active} active`;
    countEl.classList.toggle('has-active', active > 0);
}

function renderSshOptionsList() {
    const list = document.getElementById('ssh-adv-list');
    if (!list) return;
    list.innerHTML = '';

    sshOptionsDraft.forEach((opt, index) => {
        const row = document.createElement('div');
        row.className = `ssh-adv-row${opt.enabled ? ' is-enabled' : ''}`;
        row.dataset.index = String(index);

        row.innerHTML = `
            <div class="ssh-adv-row-main">
                <div class="ssh-adv-meta">
                    <span class="ssh-adv-key">${sanitizeHTML(opt.key)}</span>
                    <span class="ssh-adv-desc">${sanitizeHTML(opt.description || (opt.preset ? '' : 'Custom OpenSSH option'))}</span>
                </div>
                <div class="ssh-adv-controls">
                    <input type="text" class="ssh-adv-value" value="${sanitizeHTML(opt.value || '')}" spellcheck="false" ${opt.enabled ? '' : 'disabled'}>
                    <label class="ssh-adv-switch" title="${opt.enabled ? 'Disable' : 'Enable'}">
                        <input type="checkbox" class="ssh-adv-enable" ${opt.enabled ? 'checked' : ''}>
                        <span class="ssh-adv-switch-ui"></span>
                    </label>
                    ${opt.preset ? '' : '<button type="button" class="ssh-adv-remove" title="Remove option"><i class="fas fa-times"></i></button>'}
                </div>
            </div>
        `;

        const valueInput = row.querySelector('.ssh-adv-value');
        const enableInput = row.querySelector('.ssh-adv-enable');
        const removeBtn = row.querySelector('.ssh-adv-remove');

        valueInput.addEventListener('input', () => {
            sshOptionsDraft[index].value = valueInput.value;
        });

        enableInput.addEventListener('change', () => {
            sshOptionsDraft[index].enabled = enableInput.checked;
            valueInput.disabled = !enableInput.checked;
            row.classList.toggle('is-enabled', enableInput.checked);
            updateSshAdvCount();
        });

        if (removeBtn) {
            removeBtn.addEventListener('click', () => {
                sshOptionsDraft.splice(index, 1);
                renderSshOptionsList();
                updateSshAdvCount();
            });
        }

        list.appendChild(row);
    });
}

function addCustomSshOption() {
    const keyInput = document.getElementById('ssh-adv-custom-key');
    const valueInput = document.getElementById('ssh-adv-custom-value');
    if (!keyInput || !valueInput) return;

    const key = keyInput.value.trim();
    const value = valueInput.value.trim();

    if (!isValidSshOptionKey(key)) {
        showNotification('SSH Options', 'Option name must be letters/numbers only (e.g. ServerAliveInterval).', 'error');
        return;
    }
    if (!isValidSshOptionValue(value)) {
        showNotification('SSH Options', 'Please enter a valid option value.', 'error');
        return;
    }
    if (sshOptionsDraft.some(opt => opt.key.toLowerCase() === key.toLowerCase())) {
        showNotification('SSH Options', `Option "${key}" already exists in the list.`, 'info');
        return;
    }

    sshOptionsDraft.push({
        id: `custom:${key}:${generateId()}`,
        key,
        value,
        description: 'Custom OpenSSH option',
        enabled: true,
        preset: false
    });

    keyInput.value = '';
    valueInput.value = '';
    renderSshOptionsList();
    updateSshAdvCount();
}

const sshAdvToggle = document.getElementById('ssh-adv-toggle');
if (sshAdvToggle) {
    sshAdvToggle.addEventListener('click', () => {
        const root = document.getElementById('ssh-adv');
        setSshAdvExpanded(!(root && root.classList.contains('is-open')));
    });
}

const sshAdvAddBtn = document.getElementById('ssh-adv-add-btn');
if (sshAdvAddBtn) {
    sshAdvAddBtn.addEventListener('click', addCustomSshOption);
}

['ssh-adv-custom-key', 'ssh-adv-custom-value'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            addCustomSshOption();
        }
    });
});

loadSshOptionsDraft([]);

// --- Snippets Logic (Palette Style) ---

let snippets = [];
const snippetsPalette = document.getElementById('snippets-palette');
const toggleSnippetsBtn = document.getElementById('toggle-snippets-btn');
const paletteList = document.getElementById('palette-list');
const paletteSearchInput = document.getElementById('palette-search-input');
const paletteAddBtn = document.getElementById('palette-add-btn');

const snippetModal = document.getElementById('snippet-modal');
const snippetForm = document.getElementById('snippet-form');
const snippetNameInput = document.getElementById('snippet-name');
const snippetCommandInput = document.getElementById('snippet-command');
const cancelSnippetBtn = document.getElementById('cancel-snippet-btn');
const paletteDeleteBtn = document.getElementById('palette-delete-btn');
const paletteSelectAll = document.getElementById('palette-select-all');

let editingSnippetId = null;

// Toggle Palette
if (toggleSnippetsBtn) {
    toggleSnippetsBtn.addEventListener('click', () => {
        if (snippetsPalette.classList.contains('hidden')) {
            openPalette();
        } else {
            closePalette();
        }
    });
}

function openPalette() {
    snippetsPalette.classList.remove('hidden');
    paletteSearchInput.value = '';
    paletteSearchInput.focus();
    renderSnippets();
}

function closePalette() {
    snippetsPalette.classList.add('hidden');
}

// Close palette on Esc or click outside
snippetsPalette.addEventListener('click', (e) => {
    if (e.target === snippetsPalette) {
        closePalette();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !snippetsPalette.classList.contains('hidden') && snippetModal.classList.contains('hidden')) {
        closePalette();
    }
});


// Load Snippets
async function loadSnippets() {
    try {
        snippets = await ipcRenderer.invoke('load-snippets');
        // Pre-render not needed until opened, but good for state
    } catch (err) {
        console.error('Failed to load snippets:', err);
    }
}

// Render Snippets
function renderSnippets(filter = '') {
    if (!paletteList) return;
    paletteList.innerHTML = '';
    if (paletteSelectAll) paletteSelectAll.checked = false;
    paletteDeleteBtn.classList.add('hidden');
    const filtered = snippets.filter(s =>
        s.name.toLowerCase().includes(filter.toLowerCase()) ||
        s.command.toLowerCase().includes(filter.toLowerCase())
    );

    if (filtered.length === 0) {
        paletteList.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No snippets found</div>';
        return;
    }

    filtered.forEach(snippet => {
        const item = document.createElement('div');
        item.className = 'palette-item';
        item.innerHTML = `
            <label class="checkbox-container" onclick="event.stopPropagation()">
                <input type="checkbox" class="snippet-checkbox" data-id="${sanitizeHTML(snippet.id)}">
                <span class="checkmark"></span>
            </label>
            <div class="palette-item-content" style="flex: 1;">
                <span class="palette-item-name">${sanitizeHTML(snippet.name)}</span>
                <span class="palette-item-command">${sanitizeHTML(snippet.command)}</span>
            </div>
            <div class="palette-item-actions">
                <button class="btn-icon-xs edit-snippet-btn" title="Edit">
                    <i class="fas fa-pencil-alt"></i>
                </button>
                <button class="btn-icon-xs delete-snippet-list-btn" title="Delete" style="color: var(--danger);">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;

        // Click to execute
        item.addEventListener('click', (e) => {
            if (e.target.closest('.palette-item-actions') || e.target.closest('.checkbox-container')) return;
            insertSnippet(snippet.command);
            closePalette();
        });

        // Edit button
        const editBtn = item.querySelector('.edit-snippet-btn');
        editBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            window.openSnippetModal(snippet);
        });

        // Individual Delete button
        const deleteBtn = item.querySelector('.delete-snippet-list-btn');
        deleteBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!await showConfirm({
                title: 'Delete snippet?',
                message: `Are you sure you want to delete snippet "${snippet.name}"?\n\nThis action cannot be undone.`,
                confirmText: 'Delete',
                variant: 'danger'
            })) return;

            snippets = snippets.filter(s => s.id !== snippet.id);
            await ipcRenderer.invoke('save-snippets', snippets);
            renderSnippets(paletteSearchInput.value);
        });

        // Checkbox change
        const checkbox = item.querySelector('.snippet-checkbox');
        checkbox.addEventListener('change', () => {
            updatePaletteDeleteBtn();
        });

        paletteList.appendChild(item);
    });
}

function updatePaletteDeleteBtn() {
    const checked = document.querySelectorAll('.snippet-checkbox:checked');
    if (checked.length > 0) {
        paletteDeleteBtn.classList.remove('hidden');
        paletteDeleteBtn.innerHTML = `<i class="fas fa-trash"></i> Delete (${checked.length})`;
    } else {
        paletteDeleteBtn.classList.add('hidden');
    }
}

paletteDeleteBtn.onclick = async () => {
    const checked = document.querySelectorAll('.snippet-checkbox:checked');
    if (checked.length === 0) return;

    const idsToDelete = Array.from(checked).map(cb => cb.dataset.id);
    if (!await showConfirm({
        title: checked.length === 1 ? 'Delete snippet?' : 'Delete snippets?',
        message: `Are you sure you want to delete ${checked.length} selected snippet(s)?\n\nThis action cannot be undone.`,
        confirmText: 'Delete',
        variant: 'danger'
    })) return;

    snippets = snippets.filter(s => !idsToDelete.includes(s.id));
    await ipcRenderer.invoke('save-snippets', snippets);
    renderSnippets(paletteSearchInput.value);
    paletteDeleteBtn.classList.add('hidden');
};

if (paletteSelectAll) {
    paletteSelectAll.addEventListener('change', () => {
        const checkboxes = document.querySelectorAll('.snippet-checkbox');
        checkboxes.forEach(cb => cb.checked = paletteSelectAll.checked);
        updatePaletteDeleteBtn();
    });
}

// Insert Snippet
function insertSnippet(command) {
    if (!activeSessionId || !sessions[activeSessionId]) {
        console.warn('No active terminal session');
        return;
    }

    const data = command + '\n';

    if (broadcastMode) {
        Object.values(sessions).forEach(session => {
            if (session.pid) {
                ipcRenderer.send('terminal-write', { pid: session.pid, data });
            }
        });
    } else {
        const session = sessions[activeSessionId];
        if (session && session.pid) {
            ipcRenderer.send('terminal-write', { pid: session.pid, data });
        }
    }

    // Focus the active terminal
    if (sessions[activeSessionId] && sessions[activeSessionId].term) {
        sessions[activeSessionId].term.focus();
    }
}

// Modal Logic
window.openSnippetModal = function (snippet = null) {
    const titleEl = snippetModal.querySelector('h3');
    if (snippet) {
        editingSnippetId = snippet.id;
        snippetNameInput.value = snippet.name;
        snippetCommandInput.value = snippet.command;
        if (titleEl) titleEl.innerText = 'Edit Snippet';
    } else {
        editingSnippetId = null;
        snippetForm.reset();
        if (titleEl) titleEl.innerText = 'Create Snippet';
    }
    snippetModal.classList.remove('hidden');
    snippetNameInput.focus();
}

window.closeSnippetModal = function () {
    snippetModal.classList.add('hidden');
    snippetForm.reset();
    editingSnippetId = null;
    // If palette was open, re-render it to show changes
    if (!snippetsPalette.classList.contains('hidden')) {
        renderSnippets(paletteSearchInput.value);
        paletteSearchInput.focus();
    }
}

if (paletteAddBtn) {
    paletteAddBtn.onclick = () => window.openSnippetModal(null);
}

if (cancelSnippetBtn) {
    cancelSnippetBtn.onclick = window.closeSnippetModal;
}

if (snippetForm) {
    snippetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = snippetNameInput.value.trim();
        const command = snippetCommandInput.value.trim();

        if (!name || !command) return;

        if (editingSnippetId) {
            // Update existing
            const index = snippets.findIndex(s => s.id === editingSnippetId);
            if (index !== -1) {
                snippets[index] = { ...snippets[index], name, command };
            }
        } else {
            // Create new
            const newSnippet = {
                id: Date.now().toString(),
                name,
                command
            };
            snippets.push(newSnippet);
        }

        await ipcRenderer.invoke('save-snippets', snippets);
        window.closeSnippetModal();
        // If palette is open, refresh it
        if (!snippetsPalette.classList.contains('hidden')) {
            renderSnippets(paletteSearchInput.value);
        }
    });
}

// Delete button logic removed from modal as per user request

if (paletteSearchInput) {
    paletteSearchInput.addEventListener('input', (e) => {
        renderSnippets(e.target.value);
    });

    // Enter to run first item
    paletteSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const firstItem = paletteList.querySelector('.palette-item');
            if (firstItem) {
                firstItem.click();
            }
        }
    });
}

// Quick Actions Listeners
const qaNew = document.getElementById('qa-new');
if (qaNew) {
    qaNew.onclick = () => {
        console.log('New Connection clicked');
        document.getElementById('add-btn').click();
    };
}

const qaImport = document.getElementById('qa-import');
if (qaImport) {
    qaImport.onclick = () => {
        console.log('Import Data clicked');
        document.getElementById('import-btn').click();
    };
}

// Initial Load
loadSnippets();
init();
