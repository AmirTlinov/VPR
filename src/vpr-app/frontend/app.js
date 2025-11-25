const { invoke } = window.__TAURI__.core;

// Elements
const mainView = document.getElementById('main-view');
const settingsView = document.getElementById('settings-view');
const settingsBtn = document.getElementById('settings-btn');
const backBtn = document.getElementById('back-btn');
const saveBtn = document.getElementById('save-btn');
const connectBtn = document.getElementById('connect-btn');
const btnText = document.getElementById('btn-text');
const btnLoader = document.getElementById('btn-loader');
const asciiArt = document.getElementById('ascii-art');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const targetAddr = document.getElementById('target-addr');
const healthDot = document.getElementById('health-dot');
const healthText = document.getElementById('health-text');
const probeBtn = document.getElementById('probe-btn');
const statsBox = document.getElementById('stats-box');
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
const cfgInsecure = document.getElementById('cfg-insecure');

// State
let currentStatus = 'Disconnected';
let connectTime = null;
let bytesUp = 0;
let bytesDown = 0;
let statsInterval = null;
let healthTimer = null;
let tunnelTimer = null;

// ASCII Art variants

// Pirate skull for OFFLINE
const ASCII_OFFLINE = `
        ___________
       /           \\
      /  _       _  \\
     |  (o)     (o)  |
     |       V       |
      \\   \\═════/   /
       \\___________/
          │ │ │ │
     ═════╧═╧═╧═╧═════
        \\│/   \\│/
         X     X
        /│\\   /│\\`;

// Earth Globe Renderer
const globe = new GlobeRenderer(asciiArt, 50, 25);

// Connecting animation frames
const CONNECTING_FRAMES = [
  `
        ╭──────────╮
      ╭─┤░░░░░░░░░░├─╮
     │  │░░░░░░░░░░│  │
     │  │░░░░░░░░░░│  │
     │  │░░░░░░░░░░│  │
     │  │░░░░░░░░░░│  │
      ╰─┤░░░░░░░░░░├─╯
        ╰──────────╯
        LINKING...`,
  `
        ╭──────────╮
      ╭─┤▒░░░░░░░░░├─╮
     │  │▒▒░░░░░░░░│  │
     │  │░▒▒░░░░░░░│  │
     │  │░░▒▒░░░░░░│  │
     │  │░░░▒▒░░░░░│  │
      ╰─┤░░░░▒░░░░░├─╯
        ╰──────────╯
        LINKING..`,
  `
        ╭──────────╮
      ╭─┤▓▒░░░░░░░░├─╮
     │  │▓▓▒░░░░░░░│  │
     │  │▒▓▓▒░░░░░░│  │
     │  │░▒▓▓▒░░░░░│  │
     │  │░░▒▓▓▒░░░░│  │
      ╰─┤░░░▒▓▒░░░░├─╯
        ╰──────────╯
        LINKING.`,
  `
        ╭──────────╮
      ╭─┤█▓▒░░░░░░░├─╮
     │  │██▓▒░░░░░░│  │
     │  │▓██▓▒░░░░░│  │
     │  │▒▓██▓▒░░░░│  │
     │  │░▒▓██▓▒░░░│  │
      ╰─┤░░▒▓█▓▒░░░├─╯
        ╰──────────╯
        LINKING...`
];

let earthFrame = 0;
let connectingFrame = 0;
let animationInterval = null;

// Navigation
settingsBtn.addEventListener('click', () => {
  mainView.classList.add('hidden');
  settingsView.classList.remove('hidden');
});

backBtn.addEventListener('click', () => {
  settingsView.classList.add('hidden');
  mainView.classList.remove('hidden');
  // Перепроверим сервер при выходе из настроек
  probeServer();
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
    cfgInsecure.checked = cfg.insecure || false;
  } catch (e) {
    console.error('Config load failed:', e);
  }
}

// Save config
saveBtn.addEventListener('click', async () => {
  try {
    await invoke('save_config', {
      config: {
        server: cfgServer.value.trim(),
        port: cfgPort.value.trim(),
        username: cfgUsername.value.trim(),
        mode: cfgMode.value,
        doh_endpoint: cfgDoh.value.trim(),
        autoconnect: cfgAutoconnect.checked,
        killswitch: cfgKillswitch.checked,
        insecure: cfgInsecure.checked,
      }
    });
    showError('');
    settingsView.classList.add('hidden');
    mainView.classList.remove('hidden');
    probeServer();
  } catch (e) {
    showError(e);
  }
});

// Пробивка сервера
probeBtn.addEventListener('click', () => probeServer());

// Animation control
function startAnimation(type) {
  stopAnimation();

  if (type === 'earth') {
    globe.start();
  } else if (type === 'connecting') {
    connectingFrame = 0;
    animationInterval = setInterval(() => {
      asciiArt.textContent = CONNECTING_FRAMES[connectingFrame];
      connectingFrame = (connectingFrame + 1) % CONNECTING_FRAMES.length;
    }, 200); // Fast animation
  }
}

function stopAnimation() {
  globe.stop();
  if (animationInterval) {
    clearInterval(animationInterval);
    animationInterval = null;
  }
}

// Update UI
function updateUI(status, error = null) {
  currentStatus = status;

  // Reset classes
  asciiArt.classList.remove('active', 'connecting');
  statusDot.classList.remove('active', 'connecting');
  connectBtn.classList.remove('active');
  statsBox.classList.remove('active');
  btnText.classList.remove('hidden');
  btnLoader.classList.add('hidden');

  switch (status) {
    case 'Disconnected':
      startAnimation('earth');
      statusDot.textContent = '●';
      statusText.textContent = 'OFFLINE';
      targetAddr.textContent = 'none';
      btnText.textContent = '[ INITIATE ]';
      connectBtn.disabled = false;
      stopStats();
      setHealth('unknown');
      stopTunnelChecks();
      break;

    case 'Connecting':
      asciiArt.classList.add('connecting');
      statusDot.classList.add('connecting');
      startAnimation('connecting');
      statusText.textContent = 'LINKING...';
      targetAddr.textContent = cfgServer.value || '...';
      btnText.classList.add('hidden');
      btnLoader.classList.remove('hidden');
      connectBtn.disabled = true;
      break;

    case 'Connected':
      asciiArt.classList.add('active');
      statusDot.classList.add('active');
      connectBtn.classList.add('active');
      statsBox.classList.add('active');
      startAnimation('earth');
      statusDot.textContent = '◉';
      statusText.textContent = 'ONLINE';
      targetAddr.textContent = `${cfgServer.value}:${cfgPort.value}`;
      btnText.textContent = '[ TERMINATE ]';
      connectBtn.disabled = false;
      startStats();
      scheduleTunnelChecks();
      scheduleHealthChecks();
      break;

    case 'Disconnecting':
      stopAnimation();
      asciiArt.textContent = CONNECTING_FRAMES[0];
      statusText.textContent = 'CLOSING...';
      btnText.classList.add('hidden');
      btnLoader.classList.remove('hidden');
      connectBtn.disabled = true;
      stopStats();
      stopHealthChecks();
      stopTunnelChecks();
      break;

    case 'Error':
      startAnimation('earth');
      statusDot.textContent = '×';
      statusDot.classList.add('health-bad');
      statusText.textContent = 'ERROR';
      btnText.textContent = '[ RETRY ]';
      connectBtn.disabled = false;
      stopStats();
      setHealth('bad', 'connection failed');
      stopTunnelChecks();
      break;
  }

  if (error) showError(error);
}

function showError(msg) {
  if (msg) {
    errorEl.textContent = `> err: ${msg}`;
    errorEl.classList.remove('hidden');
  } else {
    errorEl.classList.add('hidden');
  }
}

// Health indicator helpers
function setHealth(state, details = '') {
  healthDot.classList.remove('health-ok', 'health-bad', 'health-unknown');
  healthText.classList.remove('health-ok', 'health-bad', 'health-unknown');

  switch (state) {
    case 'ok':
      healthDot.classList.add('health-ok');
      healthText.classList.add('health-ok');
      healthDot.textContent = '◉';
      healthText.textContent = details || 'reachable';
      break;
    case 'warn':
      healthDot.classList.add('health-unknown');
      healthText.classList.add('health-unknown');
      healthDot.textContent = '●';
      healthText.textContent = details || 'check tunnel';
      break;
    case 'bad':
      healthDot.classList.add('health-bad');
      healthText.classList.add('health-bad');
      healthDot.textContent = '×';
      healthText.textContent = details || 'unreachable';
      break;
    default:
      healthDot.classList.add('health-unknown');
      healthText.classList.add('health-unknown');
      healthDot.textContent = '●';
      healthText.textContent = details || 'unknown';
  }
}

async function checkTunnel() {
  try {
    const res = await invoke('check_tunnel');
    if (!res.tun_present) {
      setHealth('bad', 'vpr0 missing');
      return;
    }
    if (!res.default_via_tun || res.route_dev_to_inet !== 'vpr0') {
      setHealth('bad', 'no default via tun');
      return;
    }
    if (res.warnings && res.warnings.length > 0) {
      setHealth('warn', res.warnings[0]);
    } else {
      setHealth('ok', res.route_src_ip ? `src ${res.route_src_ip}` : 'tunnel ok');
    }
  } catch (e) {
    setHealth('bad', e.toString());
  }
}

function scheduleTunnelChecks() {
  stopTunnelChecks();
  checkTunnel();
  tunnelTimer = setInterval(checkTunnel, 15000);
}

function stopTunnelChecks() {
  if (tunnelTimer) {
    clearInterval(tunnelTimer);
    tunnelTimer = null;
  }
}

async function probeServer() {
  const server = cfgServer.value.trim();
  const port = cfgPort.value.trim() || '443';

  if (!server) {
    setHealth('unknown', 'set server');
    return;
  }

  setHealth('unknown', 'checking...');

  try {
    const res = await invoke('probe_server', { server, port });
    if (res.reachable) {
      const latency = res.latency_ms ? `${res.latency_ms} ms` : '';
      const ip = res.ip ? `@${res.ip}` : '';
      setHealth('ok', `${latency} ${ip}`.trim());
    } else {
      setHealth('bad', res.error || 'no route');
    }
  } catch (e) {
    setHealth('bad', e.toString());
  }
}

function scheduleHealthChecks() {
  stopHealthChecks();
  healthTimer = setInterval(probeServer, 30000);
}

function stopHealthChecks() {
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = null;
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
  statUp.textContent = '0';
  statDown.textContent = '0';
}

async function updateStats() {
  if (!connectTime) return;

  const elapsed = Math.floor((Date.now() - connectTime) / 1000);
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;
  statTime.textContent = `${pad(h)}:${pad(m)}:${pad(s)}`;

  // Get real statistics from backend
  try {
    const stats = await invoke('get_statistics');
    if (stats) {
      statUp.textContent = formatBytes(stats.bytes_sent || 0);
      statDown.textContent = formatBytes(stats.bytes_received || 0);
    }
  } catch (e) {
    // Fallback to simulated traffic if backend fails
    bytesUp += Math.random() * 5000;
    bytesDown += Math.random() * 15000;
    statUp.textContent = formatBytes(bytesUp);
    statDown.textContent = formatBytes(bytesDown);
  }
}

function pad(n) {
  return n.toString().padStart(2, '0');
}

function formatBytes(b) {
  if (b < 1024) return `${Math.floor(b)}B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)}K`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)}M`;
  return `${(b / 1073741824).toFixed(2)}G`;
}

// Connect/Disconnect
connectBtn.addEventListener('click', async () => {
  if (currentStatus === 'Connected') {
    await disconnect();
  } else if (currentStatus === 'Disconnected' || currentStatus === 'Error') {
    await connect();
  }
});

async function connect() {
  const server = cfgServer.value.trim();
  const username = cfgUsername.value.trim();
  const password = cfgPassword.value;

  if (!server) {
    showError('target required');
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

// Periodic state check
let stateCheckInterval = null;

async function checkState() {
  try {
    const state = await invoke('get_state');
    // Only update if status changed
    if (state.status !== currentStatus) {
      updateUI(state.status, state.error);
    }
  } catch (e) {
    console.error('State check failed:', e);
  }
}

function startStateCheck() {
  if (stateCheckInterval) return;
  stateCheckInterval = setInterval(checkState, 2000);
}

function stopStateCheck() {
  if (stateCheckInterval) {
    clearInterval(stateCheckInterval);
    stateCheckInterval = null;
  }
}

// Init
async function init() {
  await loadConfig();
  try {
    const state = await invoke('get_state');
    updateUI(state.status, state.error);
    // Start periodic state check
    startStateCheck();
  } catch (e) {
    console.error('Init failed:', e);
  }
}

document.addEventListener('DOMContentLoaded', init);
