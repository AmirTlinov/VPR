const { invoke } = window.__TAURI__.core;

// Elements
const mainView = document.getElementById('main-view');
const settingsView = document.getElementById('settings-view');
const settingsBtn = document.getElementById('settings-btn');
const backBtn = document.getElementById('back-btn');
const saveBtn = document.getElementById('save-btn');
const connectBtn = document.getElementById('connect-btn');
const shield = document.getElementById('shield');
const statusLabel = document.getElementById('status-label');
const statusServer = document.getElementById('status-server');
const stats = document.getElementById('stats');
const statTime = document.getElementById('stat-time');
const statUp = document.getElementById('stat-up');
const statDown = document.getElementById('stat-down');
const errorEl = document.getElementById('error');

// Config inputs
const cfgServer = document.getElementById('cfg-server');
const cfgPort = document.getElementById('cfg-port');
const cfgUsername = document.getElementById('cfg-username');
const cfgPassword = document.getElementById('cfg-password');
const cfgMode = document.getElementById('cfg-mode');
const cfgDoh = document.getElementById('cfg-doh');
const cfgAutoconnect = document.getElementById('cfg-autoconnect');
const cfgKillswitch = document.getElementById('cfg-killswitch');

// State
let currentStatus = 'Disconnected';
let connectTime = null;
let bytesUp = 0;
let bytesDown = 0;
let statsInterval = null;

// ASCII shields
const SHIELD_OFF = `
   .---.
  /     \\
 |   o   |
 |       |
  \\     /
   '---'`;

const SHIELD_ON = `
   .---.
  /  *  \\
 |  ***  |
 |  ***  |
  \\  *  /
   '---'`;

const SHIELD_BUSY = `
   .---.
  /     \\
 |  ~~~  |
 |  ~~~  |
  \\     /
   '---'`;

// Navigation
settingsBtn.addEventListener('click', () => {
  mainView.classList.add('hidden');
  settingsView.classList.remove('hidden');
});

backBtn.addEventListener('click', () => {
  settingsView.classList.add('hidden');
  mainView.classList.remove('hidden');
});

// Load config
async function loadConfig() {
  try {
    const cfg = await invoke('get_config');
    cfgServer.value = cfg.server || '';
    cfgPort.value = cfg.port || '443';
    cfgUsername.value = cfg.username || '';
    cfgMode.value = cfg.mode || 'masque';
    cfgDoh.value = cfg.doh_endpoint || '/dns-query';
    cfgAutoconnect.checked = cfg.autoconnect || false;
    cfgKillswitch.checked = cfg.killswitch || false;
  } catch (e) {
    console.error('Failed to load config:', e);
  }
}

// Save config
saveBtn.addEventListener('click', async () => {
  try {
    await invoke('save_config', {
      server: cfgServer.value.trim(),
      port: cfgPort.value.trim(),
      username: cfgUsername.value.trim(),
      mode: cfgMode.value,
      dohEndpoint: cfgDoh.value.trim(),
      autoconnect: cfgAutoconnect.checked,
      killswitch: cfgKillswitch.checked,
    });
    showError('');
    settingsView.classList.add('hidden');
    mainView.classList.remove('hidden');
  } catch (e) {
    showError(e);
  }
});

// Update UI
function updateUI(status, error = null) {
  currentStatus = status;

  shield.classList.remove('connected', 'connecting');
  statusLabel.classList.remove('connected', 'connecting');
  connectBtn.classList.remove('connected');
  stats.classList.remove('active');

  switch (status) {
    case 'Disconnected':
      shield.textContent = SHIELD_OFF;
      statusLabel.textContent = 'DISCONNECTED';
      statusServer.textContent = '-';
      connectBtn.textContent = '[ CONNECT ]';
      connectBtn.disabled = false;
      stopStats();
      break;

    case 'Connecting':
      shield.classList.add('connecting');
      statusLabel.classList.add('connecting');
      shield.textContent = SHIELD_BUSY;
      statusLabel.textContent = 'CONNECTING...';
      statusServer.textContent = cfgServer.value || '-';
      connectBtn.textContent = '[ ... ]';
      connectBtn.disabled = true;
      break;

    case 'Connected':
      shield.classList.add('connected');
      statusLabel.classList.add('connected');
      connectBtn.classList.add('connected');
      stats.classList.add('active');
      shield.textContent = SHIELD_ON;
      statusLabel.textContent = 'PROTECTED';
      statusServer.textContent = cfgServer.value || '-';
      connectBtn.textContent = '[ DISCONNECT ]';
      connectBtn.disabled = false;
      startStats();
      break;

    case 'Disconnecting':
      shield.textContent = SHIELD_BUSY;
      statusLabel.textContent = 'DISCONNECTING...';
      connectBtn.textContent = '[ ... ]';
      connectBtn.disabled = true;
      stopStats();
      break;
  }

  if (error) {
    showError(error);
  }
}

function showError(msg) {
  if (msg) {
    errorEl.textContent = msg;
    errorEl.classList.remove('hidden');
  } else {
    errorEl.classList.add('hidden');
  }
}

// Stats
function startStats() {
  connectTime = Date.now();
  bytesUp = 0;
  bytesDown = 0;
  updateStats();
  statsInterval = setInterval(updateStats, 1000);
}

function stopStats() {
  if (statsInterval) {
    clearInterval(statsInterval);
    statsInterval = null;
  }
  statTime.textContent = '--:--:--';
  statUp.textContent = '-';
  statDown.textContent = '-';
}

function updateStats() {
  if (!connectTime) return;

  const elapsed = Math.floor((Date.now() - connectTime) / 1000);
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;
  statTime.textContent = `${pad(h)}:${pad(m)}:${pad(s)}`;

  // Simulate traffic (TODO: get real stats from backend)
  bytesUp += Math.random() * 5000;
  bytesDown += Math.random() * 15000;
  statUp.textContent = formatBytes(bytesUp);
  statDown.textContent = formatBytes(bytesDown);
}

function pad(n) {
  return n.toString().padStart(2, '0');
}

function formatBytes(b) {
  if (b < 1024) return `${Math.floor(b)} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// Connect/Disconnect
connectBtn.addEventListener('click', async () => {
  if (currentStatus === 'Connected') {
    await disconnect();
  } else if (currentStatus === 'Disconnected') {
    await connect();
  }
});

async function connect() {
  const server = cfgServer.value.trim();
  const username = cfgUsername.value.trim();
  const password = cfgPassword.value;

  if (!server) {
    showError('Server address required');
    settingsView.classList.remove('hidden');
    mainView.classList.add('hidden');
    return;
  }

  showError('');
  updateUI('Connecting');

  try {
    await invoke('connect', {
      server,
      port: cfgPort.value.trim() || '443',
      username,
      password,
      mode: cfgMode.value,
    });
    updateUI('Connected');
    cfgPassword.value = '';
  } catch (e) {
    updateUI('Disconnected', e);
  }
}

async function disconnect() {
  updateUI('Disconnecting');
  try {
    await invoke('disconnect');
    updateUI('Disconnected');
  } catch (e) {
    updateUI('Connected', e);
  }
}

// Init
async function init() {
  await loadConfig();

  try {
    const state = await invoke('get_state');
    updateUI(state.status, state.error);
  } catch (e) {
    console.error('Failed to get state:', e);
  }
}

document.addEventListener('DOMContentLoaded', init);
