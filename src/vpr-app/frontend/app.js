/**
 * VPR - Flagship Premium VPN
 *
 * Flow:
 * 1. User enters server IP + SSH credentials
 * 2. Click "Connect" -> Auto-deploy VPN server if needed -> Connect
 * 3. Done!
 *
 * Features:
 * - Interactive particle globe with shaders
 * - State-based animations
 * - Glassmorphism UI with micro-animations
 * - Smooth transitions and countup animations
 */

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// =============================================================================
// DOM Elements
// =============================================================================

const mainView = document.getElementById('main-view');
const settingsView = document.getElementById('settings-view');
const settingsBtn = document.getElementById('settings-btn');
const backBtn = document.getElementById('back-btn');

// Globe
const globeCard = document.getElementById('globe-card');
const globeContainer = document.getElementById('globe-container');

// Status
const statusIcon = document.getElementById('status-icon');
const statusLabel = document.getElementById('status-label');
const statusDetails = document.getElementById('status-details');

// Setup
const setupCard = document.getElementById('setup-card');
const serverSelect = document.getElementById('server-select');
const headerServerSelect = document.getElementById('header-server-select');
const deleteServerBtn = document.getElementById('delete-server-btn');

// Custom Dropdown
const serverDropdown = document.getElementById('server-dropdown');
const dropdownTrigger = document.getElementById('dropdown-trigger');
const dropdownValue = document.getElementById('dropdown-value');
const dropdownMenu = document.getElementById('dropdown-menu');
const newServerForm = document.getElementById('new-server-form');
const serverInput = document.getElementById('server-input');
const userInput = document.getElementById('user-input');
const portInput = document.getElementById('port-input');
const passInput = document.getElementById('pass-input');
const setupTitle = document.getElementById('setup-title');

// Stats
const statsCard = document.getElementById('stats-card');
const statTime = document.getElementById('stat-time');
const statUp = document.getElementById('stat-up');
const statDown = document.getElementById('stat-down');

// Progress
const progressCard = document.getElementById('progress-card');
const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');
const logArea = document.getElementById('log-area');

// Log Card
const logCard = document.getElementById('log-card');
const connectionLog = document.getElementById('connection-log');
const logToggleBtn = document.getElementById('log-toggle-btn');

// Button
const mainBtn = document.getElementById('main-btn');
const btnText = document.getElementById('btn-text');
const btnLoader = document.getElementById('btn-loader');

// Error
const errorBox = document.getElementById('error-box');
const errorText = document.getElementById('error-text');
const errorClose = document.getElementById('error-close');

// Settings
const cfgKillswitch = document.getElementById('cfg-killswitch');
const cfgAutoconnect = document.getElementById('cfg-autoconnect');
const cfgInsecure = document.getElementById('cfg-insecure');
const cfgVpnPort = document.getElementById('cfg-vpn-port');
const cfgMode = document.getElementById('cfg-mode');
const reinstallBtn = document.getElementById('reinstall-btn');
const uninstallBtn = document.getElementById('uninstall-btn');

// =============================================================================
// State
// =============================================================================

let currentState = 'disconnected'; // disconnected, deploying, connecting, connected, error
let connectTime = null;
let statsInterval = null;
let serverDeployed = false;
let servers = []; // List of saved servers
let selectedServerIndex = null; // Currently selected server index
let globe = null; // Canvas particle globe instance

// Stats animation values
let animatedStats = {
  bytesUp: 0,
  bytesDown: 0,
  targetUp: 0,
  targetDown: 0
};

// =============================================================================
// Icons (legacy fallback)
// =============================================================================

const ICONS = {
  shield: `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>`,
  shieldCheck: `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    <polyline points="9 12 11 14 15 10"></polyline>
  </svg>`,
  shieldX: `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    <line x1="9" y1="9" x2="15" y2="15"></line>
    <line x1="15" y1="9" x2="9" y2="15"></line>
  </svg>`
};

// =============================================================================
// UI Updates
// =============================================================================

function updateUI(state, details = {}) {
  currentState = state;

  // Update canvas particle globe state
  if (globe) {
    if (state === 'connecting' || state === 'deploying') {
      globe.setState('connecting');
    } else if (state === 'connected') {
      globe.setState('connected');
    } else if (state === 'error') {
      globe.setState('error');
    } else {
      globe.setState('disconnected');
    }
  }

  // Update globe-card classes for CSS styling
  if (globeCard) {
    globeCard.classList.remove('connecting', 'connected', 'error');
    if (state === 'connecting' || state === 'deploying') {
      globeCard.classList.add('connecting');
    } else if (state === 'connected') {
      globeCard.classList.add('connected');
    } else if (state === 'error') {
      globeCard.classList.add('error');
    }
  }

  // Reset all states
  statusIcon.classList.remove('connected', 'connecting', 'error');
  mainBtn.classList.remove('connected');
  // Don't touch setupCard/statsCard here - managed by selectServer/showNewServerForm
  progressCard.classList.add('hidden');
  logCard.classList.add('hidden');
  btnText.classList.remove('hidden');
  btnLoader.classList.add('hidden');
  mainBtn.disabled = false;

  switch (state) {
    case 'disconnected':
      statusIcon.innerHTML = ICONS.shield;
      statusLabel.textContent = 'Not Connected';
      if (selectedServerIndex !== null && servers[selectedServerIndex]) {
        const s = servers[selectedServerIndex];
        statusDetails.textContent = s.deployed
          ? `Server ready: ${s.name || s.host}`
          : 'Configure server below';
      } else {
        statusDetails.textContent = 'Add a server to get started';
      }
      btnText.textContent = 'Connect';
      break;

    case 'deploying':
      statusIcon.classList.add('connecting');
      statusIcon.innerHTML = ICONS.shield;
      statusLabel.textContent = 'Setting Up...';
      statusDetails.textContent = details.message || 'Installing VPN server';
      setupCard.classList.add('hidden');
      progressCard.classList.remove('hidden');
      btnText.classList.add('hidden');
      btnLoader.classList.remove('hidden');
      mainBtn.disabled = true;
      break;

    case 'connecting':
      statusIcon.classList.add('connecting');
      statusIcon.innerHTML = ICONS.shield;
      statusLabel.textContent = 'Connecting...';
      statusDetails.textContent = `Establishing secure tunnel to ${serverInput.value}`;
      setupCard.classList.add('hidden');
      btnText.classList.add('hidden');
      btnLoader.classList.remove('hidden');
      mainBtn.disabled = true;
      break;

    case 'connected':
      statusIcon.classList.add('connected');
      statusIcon.innerHTML = ICONS.shieldCheck;
      statusLabel.textContent = 'Protected';
      statusDetails.textContent = `Connected to ${serverInput.value}`;
      setupCard.classList.add('hidden');
      statsCard.classList.remove('hidden');
      // Keep log collapsed by default, user can toggle
      mainBtn.classList.add('connected');
      btnText.textContent = 'Disconnect';
      startStats();
      break;

    case 'error':
      statusIcon.classList.add('error');
      statusIcon.innerHTML = ICONS.shieldX;
      statusLabel.textContent = 'Connection Failed';
      statusDetails.textContent = details.message || 'Check your settings and try again';
      // Show log on error
      logCard.classList.remove('hidden', 'collapsed');
      logToggleBtn.classList.add('active');
      btnText.textContent = 'Retry';
      stopStats();
      break;
  }
}

function showError(message) {
  errorText.textContent = message;
  errorBox.classList.remove('hidden');
}

function hideError() {
  errorBox.classList.add('hidden');
}

function updateProgress(percent, message) {
  progressFill.style.width = `${percent}%`;
  progressText.textContent = message;
}

function clearLog() {
  logArea.innerHTML = '';
  connectionLog.innerHTML = '';
}

function addLog(message, type = 'info') {
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  const text = `[${time}] ${message}`;

  // Add to progress log area
  const line1 = document.createElement('div');
  line1.className = `log-line log-${type}`;
  line1.textContent = text;
  logArea.appendChild(line1);
  logArea.scrollTop = logArea.scrollHeight;

  // Add to persistent connection log
  const line2 = document.createElement('div');
  line2.className = `log-line log-${type}`;
  line2.textContent = text;
  connectionLog.appendChild(line2);
  connectionLog.scrollTop = connectionLog.scrollHeight;
}

// =============================================================================
// Stats
// =============================================================================

function startStats() {
  connectTime = Date.now();
  animatedStats = { bytesUp: 0, bytesDown: 0, targetUp: 0, targetDown: 0 };
  updateStats();
  statsInterval = setInterval(updateStats, 1000);
  requestAnimationFrame(animateStatsFrame);
}

function stopStats() {
  if (statsInterval) {
    clearInterval(statsInterval);
    statsInterval = null;
  }
  statTime.textContent = '00:00:00';
  statUp.textContent = '0 B';
  statDown.textContent = '0 B';
}

async function updateStats() {
  if (!connectTime) return;

  const elapsed = Math.floor((Date.now() - connectTime) / 1000);
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;

  // Animate time digits
  animateValue(statTime, `${pad(h)}:${pad(m)}:${pad(s)}`);

  try {
    const stats = await invoke('get_statistics');
    if (stats) {
      animatedStats.targetUp = stats.bytes_sent || 0;
      animatedStats.targetDown = stats.bytes_received || 0;
    }
  } catch (e) {
    // Keep last values
  }
}

// Smooth countup animation for stats
function animateStatsFrame() {
  if (currentState !== 'connected') return;

  // Lerp towards target values
  const lerpFactor = 0.15;
  animatedStats.bytesUp += (animatedStats.targetUp - animatedStats.bytesUp) * lerpFactor;
  animatedStats.bytesDown += (animatedStats.targetDown - animatedStats.bytesDown) * lerpFactor;

  statUp.textContent = formatBytes(Math.floor(animatedStats.bytesUp));
  statDown.textContent = formatBytes(Math.floor(animatedStats.bytesDown));

  requestAnimationFrame(animateStatsFrame);
}

function animateValue(element, newValue) {
  if (element.textContent !== newValue) {
    element.style.transform = 'scale(1.05)';
    element.textContent = newValue;
    setTimeout(() => {
      element.style.transform = 'scale(1)';
    }, 100);
  }
}

function pad(n) {
  return n.toString().padStart(2, '0');
}

function formatBytes(b) {
  if (b < 1024) return `${Math.floor(b)} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}

// =============================================================================
// Main Action
// =============================================================================

mainBtn.addEventListener('click', async () => {
  hideError();

  if (currentState === 'connected') {
    await disconnect();
  } else if (currentState === 'disconnected' || currentState === 'error') {
    await connectFlow();
  }
});

async function connectFlow() {
  const server = serverInput.value.trim();
  const user = userInput.value.trim() || 'root';
  const port = portInput.value.trim() || '22';
  const pass = passInput.value;

  // Validate
  if (!server) {
    showError('Please enter a server address');
    serverInput.focus();
    return;
  }

  try {
    clearLog();

    // If server already deployed, skip SSH check and connect directly
    if (serverDeployed) {
      addLog(`Server ${server} already configured`, 'success');
      addLog('Connecting to VPN...', 'info');
      updateUI('connecting');
      await connectVpn(server);
      addLog('VPN connected!', 'success');
      return;
    }

    // First time setup - need SSH credentials
    if (!pass) {
      showError('First time setup requires SSH password');
      passInput.focus();
      return;
    }

    updateUI('deploying', { message: 'Checking server status...' });
    updateProgress(10, 'Checking server status...');
    addLog(`Connecting to ${server}...`, 'info');

    const vps = {
      host: server,
      ssh_port: parseInt(port, 10),
      ssh_user: user,
      ssh_password: pass,
      ssh_key_path: null,
      deployed: false
    };

    const status = await invoke('check_vps_status', { vps });
    addLog(`Server status: ${status.deployed ? 'deployed' : 'not deployed'}, ${status.running ? 'running' : 'stopped'}`, 'info');

    if (!status.deployed) {
      // Need to deploy
      addLog('Server not deployed, starting installation...', 'warn');
      await deployServer(vps);
    } else if (!status.running) {
      // Deployed but not running - start it
      addLog('Starting VPN server...', 'info');
      updateProgress(80, 'Starting VPN server...');
      await invoke('start_vps_server', { vps });
      addLog('VPN server started', 'success');
    } else {
      addLog('VPN server is ready', 'success');
    }

    serverDeployed = true;

    // Save server to the list
    const vpsConfig = {
      host: server,
      ssh_port: parseInt(port, 10),
      ssh_user: user,
      ssh_password: null, // Don't save password
      ssh_key_path: null,
      deployed: true
    };

    if (selectedServerIndex !== null) {
      // Update existing server
      await invoke('update_server', {
        index: selectedServerIndex,
        name: server,
        vps: vpsConfig
      });
    } else {
      // Add new server
      selectedServerIndex = await invoke('add_server', {
        name: server,
        vps: vpsConfig
      });
    }

    // Reload server list
    await loadServers();
    addLog('Server configuration saved', 'info');

    // Clear password from input after successful setup
    passInput.value = '';

    // Now connect
    addLog('Establishing VPN tunnel...', 'info');
    await connectVpn(server);
    addLog('VPN connected!', 'success');

  } catch (e) {
    addLog(`Error: ${e.toString()}`, 'error');
    updateUI('error', { message: e.toString() });
    showError(e.toString());
  }
}

async function deployServer(vps) {
  updateProgress(20, 'Connecting to server...');
  addLog(`Testing SSH connection to ${vps.host}:${vps.ssh_port}...`, 'info');

  // Test connection first
  try {
    await invoke('test_vps_connection', { vps });
    addLog('SSH connection successful', 'success');
  } catch (e) {
    addLog(`SSH failed: ${e}`, 'error');
    throw new Error(`Cannot connect to ${vps.host}: ${e}`);
  }

  updateProgress(30, 'Installing VPN server...');
  addLog('Deploying VPN server (this may take a few minutes)...', 'info');

  // Deploy
  await invoke('deploy_server', { vps });

  updateProgress(90, 'Deployment complete!');
  addLog('Deployment complete!', 'success');
}

async function connectVpn(server) {
  updateUI('connecting');

  const vpnPort = cfgVpnPort.value.trim() || '4433';

  await invoke('connect', {
    server,
    port: vpnPort,
    username: '',
    password: '',
    mode: cfgMode.value || 'masque'
  });

  // Clear password after successful connection
  passInput.value = '';

  updateUI('connected');
}

async function disconnect() {
  updateUI('connecting');
  statusLabel.textContent = 'Disconnecting...';

  try {
    await invoke('disconnect');
    updateUI('disconnected');
  } catch (e) {
    updateUI('connected');
    showError(e.toString());
  }
}

// =============================================================================
// Progress Events
// =============================================================================

listen('deploy_progress', (event) => {
  const { percent, message, error } = event.payload;
  updateProgress(percent, message);
  addLog(message, error ? 'error' : 'info');
  if (error) {
    updateUI('error', { message: error });
    showError(error);
  }
});

// VPN connection progress
listen('vpn_progress', (event) => {
  const { message, status } = event.payload;
  const type = status === 'error' ? 'error' : status === 'success' ? 'success' : 'info';
  addLog(message, type);
});

// Diagnostic results - показываем детальную информацию о проблемах
listen('diagnostic_result', (event) => {
  const result = event.payload;
  console.log('Diagnostic result:', result);

  // Логируем каждую проверку
  for (const check of result.checks) {
    let icon = '✓';
    let type = 'success';

    if (check.status === 'Failed') {
      icon = '✗';
      type = 'error';
    } else if (check.status === 'Warning') {
      icon = '⚠';
      type = 'warn';
    }

    addLog(`${icon} [${check.name}] ${check.message}`, type);

    // Показываем детали для ошибок
    if (check.details && check.status === 'Failed') {
      const lines = check.details.split('\n');
      for (const line of lines) {
        if (line.trim()) {
          addLog(`   ${line}`, 'info');
        }
      }
    }
  }

  // Показываем итоговое сообщение
  if (result.status === 'Failed') {
    addLog(`── Diagnosis: ${result.summary}`, 'error');
    if (result.action) {
      addLog(`── Action: ${result.action}`, 'warn');
    }
  }
});

// Comprehensive diagnostic results - flagship level
listen('comprehensive_diagnostic_result', (event) => {
  const result = event.payload;
  console.log('Comprehensive diagnostic result:', result);

  addLog('═══════════════════════════════════════════', 'info');
  addLog(`FLAGSHIP DIAGNOSTICS COMPLETE (${result.total_duration_ms}ms)`, 'info');
  addLog('═══════════════════════════════════════════', 'info');

  // Overall status
  const statusIcon = result.overall_status === 'Passed' ? '✓' :
                     result.overall_status === 'Warning' ? '⚠' : '✗';
  const statusType = result.overall_status === 'Passed' ? 'success' :
                     result.overall_status === 'Warning' ? 'warn' : 'error';
  addLog(`${statusIcon} Overall: ${result.overall_message}`, statusType);

  // Connection quality
  if (result.connection_quality) {
    const q = result.connection_quality;
    addLog(`📊 Quality: ${q.quality_label} (Score: ${q.quality_score}/100)`, 'info');
    addLog(`   RTT: ${q.rtt_ms.toFixed(1)}ms, Jitter: ${q.rtt_jitter_ms.toFixed(1)}ms, Loss: ${q.packet_loss_percent.toFixed(1)}%`, 'info');
  }

  // QUIC diagnostic
  if (result.quic_diagnostic) {
    const qd = result.quic_diagnostic;
    if (qd.initial_handshake.completed) {
      addLog(`🔐 QUIC: Initial handshake OK (${qd.initial_handshake.duration_ms}ms)`, 'success');
      if (qd.quic_version) {
        addLog(`   QUIC version: ${qd.quic_version}`, 'info');
      }
    } else if (qd.initial_handshake.error) {
      addLog(`🔐 QUIC: ${qd.initial_handshake.error}`, 'error');
    }
  }

  // Local certificate
  if (result.local_certificate) {
    const cert = result.local_certificate;
    if (cert.exists && cert.valid) {
      const expiryMsg = cert.days_until_expiry ?
        ` (expires in ${cert.days_until_expiry} days)` : '';
      if (cert.warning) {
        addLog(`📜 Certificate: Valid${expiryMsg} ⚠ ${cert.warning}`, 'warn');
      } else {
        addLog(`📜 Certificate: Valid${expiryMsg}`, 'success');
      }
    } else if (cert.error) {
      addLog(`📜 Certificate: ${cert.error}`, 'error');
    }
  }

  // Server diagnostics (if available)
  if (result.server_diagnostic) {
    const sd = result.server_diagnostic;
    addLog('───── Remote Server Status ─────', 'info');
    addLog(`   VPN Server: ${sd.vpn_server_running ? 'Running' : 'Not Running'}`, sd.vpn_server_running ? 'success' : 'error');
    if (sd.vpn_listening_port) {
      addLog(`   Listening on port: ${sd.vpn_listening_port}`, 'info');
    }
    addLog(`   Firewall: ${sd.firewall_open ? 'Open' : 'May be blocking'}`, sd.firewall_open ? 'success' : 'warn');
    if (sd.system_resources.load_average) {
      addLog(`   Load: ${sd.system_resources.load_average}`, 'info');
    }
    if (sd.uptime) {
      addLog(`   Uptime: ${sd.uptime}`, 'info');
    }
    if (sd.errors.length > 0) {
      for (const err of sd.errors) {
        addLog(`   Error: ${err}`, 'error');
      }
    }
  }

  // Available fixes
  if (result.available_fixes && result.available_fixes.length > 0) {
    addLog('───── Available Auto-Fixes ─────', 'warn');
    for (const fix of result.available_fixes) {
      addLog(`   🔧 ${fix.name}: ${fix.description}`, 'info');
      if (fix.safe) {
        addLog(`      Command: ${fix.command}`, 'info');
      }
    }
  }

  addLog('═══════════════════════════════════════════', 'info');
});

// Connection quality measurement result
listen('connection_quality_result', (event) => {
  const q = event.payload;
  addLog(`📊 Connection Quality: ${q.quality_label}`, 'info');
  addLog(`   Score: ${q.quality_score}/100, RTT: ${q.rtt_ms.toFixed(1)}ms`, 'info');
});

// =============================================================================
// Settings
// =============================================================================

settingsBtn.addEventListener('click', () => {
  mainView.classList.add('hidden');
  settingsView.classList.remove('hidden');
  // Hide header controls on settings page
  serverDropdown.classList.add('hidden');
  settingsBtn.classList.add('hidden');
  loadSettings();
});

backBtn.addEventListener('click', () => {
  saveSettings();
  settingsView.classList.add('hidden');
  mainView.classList.remove('hidden');
  // Restore header controls
  updateHeaderVisibility();
});

async function loadSettings() {
  try {
    const cfg = await invoke('get_config');
    cfgKillswitch.checked = cfg.killswitch || false;
    cfgAutoconnect.checked = cfg.autoconnect || false;
    cfgInsecure.checked = cfg.insecure || false;
    cfgVpnPort.value = cfg.port || '443';
    cfgMode.value = cfg.mode || 'masque';
  } catch (e) {
    console.error('Failed to load settings:', e);
  }
}

async function saveSettings() {
  try {
    await invoke('save_config', {
      config: {
        server: serverInput.value.trim(),
        port: cfgVpnPort.value.trim() || '443',
        username: '',
        mode: cfgMode.value,
        doh_endpoint: '/dns-query',
        autoconnect: cfgAutoconnect.checked,
        killswitch: cfgKillswitch.checked,
        insecure: cfgInsecure.checked
      }
    });
  } catch (e) {
    console.error('Failed to save settings:', e);
  }
}

// Reinstall server
reinstallBtn.addEventListener('click', async () => {
  if (!confirm('This will reinstall the VPN server. Continue?')) return;

  const server = serverInput.value.trim();
  const pass = passInput.value;

  if (!server || !pass) {
    showError('Enter server address and password first');
    settingsView.classList.add('hidden');
    mainView.classList.remove('hidden');
    return;
  }

  settingsView.classList.add('hidden');
  mainView.classList.remove('hidden');

  serverDeployed = false;
  await connectFlow();
});

// Uninstall server
uninstallBtn.addEventListener('click', async () => {
  if (!confirm('Remove VPN server from VPS? This cannot be undone.')) return;

  const server = serverInput.value.trim();
  const user = userInput.value.trim() || 'root';
  const port = portInput.value.trim() || '22';
  const pass = passInput.value;

  if (!server || !pass) {
    showError('Enter server address and password first');
    return;
  }

  try {
    await invoke('uninstall_server', {
      vps: {
        host: server,
        ssh_port: parseInt(port, 10),
        ssh_user: user,
        ssh_password: pass,
        ssh_key_path: null,
        deployed: false
      }
    });
    serverDeployed = false;
    settingsView.classList.add('hidden');
    mainView.classList.remove('hidden');
    updateUI('disconnected');
  } catch (e) {
    showError(e.toString());
  }
});

// =============================================================================
// Error handling
// =============================================================================

errorClose.addEventListener('click', hideError);

// Log toggle button - expands stats panel to show logs, hides globe
logToggleBtn.addEventListener('click', () => {
  const isExpanded = statsCard.classList.toggle('expanded');
  logToggleBtn.classList.toggle('active');

  // Hide/show globe when logs are expanded/collapsed
  if (isExpanded) {
    globeCard.classList.add('hide-globe');
  } else {
    globeCard.classList.remove('hide-globe');
    // Resize globe after it becomes visible
    if (globe) {
      setTimeout(() => globe.resize(), 50);
    }
  }
});

// =============================================================================
// Server List Management
// =============================================================================

async function loadServers() {
  try {
    servers = await invoke('get_servers');
    selectedServerIndex = await invoke('get_selected_server');
    updateServerSelect();
  } catch (e) {
    console.error('Failed to load servers:', e);
    servers = [];
  }
}

function updateServerSelect() {
  // Clear existing options except the first one for both selects
  while (serverSelect.options.length > 1) {
    serverSelect.remove(1);
  }
  while (headerServerSelect.options.length > 1) {
    headerServerSelect.remove(1);
  }

  // Add servers to both selects
  servers.forEach((server, index) => {
    const option1 = document.createElement('option');
    option1.value = index.toString();
    option1.textContent = server.name || server.host;
    serverSelect.appendChild(option1);

    const option2 = document.createElement('option');
    option2.value = index.toString();
    option2.textContent = server.name || server.host;
    headerServerSelect.appendChild(option2);
  });

  // Update custom dropdown
  updateCustomDropdown();

  // Select the appropriate option
  if (selectedServerIndex !== null && selectedServerIndex < servers.length) {
    serverSelect.value = selectedServerIndex.toString();
    headerServerSelect.value = selectedServerIndex.toString();
    selectServer(selectedServerIndex);
  } else if (servers.length > 0) {
    serverSelect.value = '0';
    headerServerSelect.value = '0';
    selectServer(0);
  } else {
    serverSelect.value = 'new';
    headerServerSelect.value = 'new';
    showNewServerForm();
  }
}

function selectServer(index) {
  selectedServerIndex = index;
  const server = servers[index];
  if (server) {
    serverInput.value = server.host || '';
    userInput.value = server.ssh_user || 'root';
    portInput.value = server.ssh_port || '22';
    passInput.value = '';
    serverDeployed = server.deployed || false;

    // Hide setup card entirely when server is selected
    setupCard.classList.add('hidden');

    // Show globe when server is selected
    globeCard.classList.remove('hide-globe');

    // Resize globe after it becomes visible (needs a small delay for CSS transition)
    if (globe) {
      setTimeout(() => globe.resize(), 50);
    }

    // Show stats card (with zeroed values when disconnected)
    statsCard.classList.remove('hidden');
  }
}

function showNewServerForm() {
  selectedServerIndex = null;
  serverInput.value = '';
  userInput.value = '';
  portInput.value = '';
  passInput.value = '';
  serverDeployed = false;

  // Show setup card with form
  setupCard.classList.remove('hidden');
  setupTitle.textContent = 'New Server';
  newServerForm.classList.remove('hidden');
  deleteServerBtn.classList.add('hidden');
  document.getElementById('ssh-fields').classList.remove('hidden');

  // Hide globe and stats when adding new server
  globeCard.classList.add('hide-globe');
  statsCard.classList.add('hidden');
}

// =============================================================================
// Custom Dropdown Functions
// =============================================================================

function updateHeaderVisibility() {
  // Hide dropdown and settings button if no servers configured
  if (servers.length === 0) {
    serverDropdown.classList.add('hidden');
    settingsBtn.classList.add('hidden');
  } else {
    serverDropdown.classList.remove('hidden');
    settingsBtn.classList.remove('hidden');
  }
}

function updateCustomDropdown() {
  // Update header visibility based on server count
  updateHeaderVisibility();

  // Clear dropdown menu except the "Add server" item
  dropdownMenu.innerHTML = '';

  // Add existing servers first
  servers.forEach((server, index) => {
    const item = document.createElement('div');
    item.className = 'dropdown-item';
    item.dataset.value = index.toString();
    if (selectedServerIndex === index) {
      item.classList.add('selected');
    }
    item.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
        <line x1="8" y1="21" x2="16" y2="21"></line>
        <line x1="12" y1="17" x2="12" y2="21"></line>
      </svg>
      <span>${server.name || server.host}</span>
      <div class="server-status${server.deployed ? ' online' : ''}"></div>
    `;
    item.addEventListener('click', () => handleDropdownSelect(index.toString()));
    dropdownMenu.appendChild(item);
  });

  // Add "Add server" item at the end
  const addItem = document.createElement('div');
  addItem.className = 'dropdown-item add-new';
  addItem.dataset.value = 'new';
  addItem.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <line x1="12" y1="5" x2="12" y2="19"></line>
      <line x1="5" y1="12" x2="19" y2="12"></line>
    </svg>
    <span>Add server</span>
  `;
  addItem.addEventListener('click', () => handleDropdownSelect('new'));
  dropdownMenu.appendChild(addItem);

  // Update displayed value
  updateDropdownValue();
}

function updateDropdownValue() {
  if (selectedServerIndex !== null && servers[selectedServerIndex]) {
    dropdownValue.textContent = servers[selectedServerIndex].name || servers[selectedServerIndex].host;
  } else {
    dropdownValue.textContent = '+ Add server';
  }
}

function handleDropdownSelect(value) {
  serverDropdown.classList.remove('open');
  handleServerSelectChange(value);
}

// Toggle dropdown open/close
dropdownTrigger.addEventListener('click', (e) => {
  e.stopPropagation();
  serverDropdown.classList.toggle('open');
});

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
  if (!serverDropdown.contains(e.target)) {
    serverDropdown.classList.remove('open');
  }
});

// Close dropdown on escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    serverDropdown.classList.remove('open');
  }
});

// Server select change handler (shared logic)
async function handleServerSelectChange(value) {
  if (value === 'new') {
    showNewServerForm();
    await invoke('set_selected_server', { index: null });
  } else {
    const index = parseInt(value, 10);
    selectServer(index);
    await invoke('set_selected_server', { index });
  }
  // Sync all selects
  serverSelect.value = value;
  headerServerSelect.value = value;
  updateDropdownValue();

  // Update selected state in dropdown
  dropdownMenu.querySelectorAll('.dropdown-item').forEach(item => {
    item.classList.toggle('selected', item.dataset.value === value);
  });

  updateUI('disconnected');
}

serverSelect.addEventListener('change', async () => {
  await handleServerSelectChange(serverSelect.value);
});

headerServerSelect.addEventListener('change', async () => {
  await handleServerSelectChange(headerServerSelect.value);
});

// Delete server button
deleteServerBtn.addEventListener('click', async () => {
  if (selectedServerIndex === null) return;

  const server = servers[selectedServerIndex];
  if (!confirm(`Delete server "${server.name || server.host}"?`)) return;

  try {
    await invoke('remove_server', { index: selectedServerIndex });
    await loadServers();
    updateUI('disconnected');
  } catch (e) {
    showError(e.toString());
  }
});

// =============================================================================
// State sync
// =============================================================================

let stateCheckInterval = null;

async function checkState() {
  try {
    const state = await invoke('get_state');

    // Sync state from backend
    if (state.status === 'Connected' && currentState !== 'connected') {
      updateUI('connected');
    } else if (state.status === 'Disconnected' && currentState === 'connected') {
      updateUI('disconnected');
    } else if (state.status === 'Error' && currentState !== 'error') {
      updateUI('error', { message: state.error });
    }
  } catch (e) {
    console.error('State check failed:', e);
  }
}

// =============================================================================
// Init
// =============================================================================

async function init() {
  // Add ripple effect to main button
  initRippleEffect();

  // Load saved config FIRST (this determines if globe will be visible)
  try {
    // Load server list - this will show/hide globe-card based on servers
    await loadServers();

    // NOW initialize Canvas Particle Globe (after hide-globe class is potentially removed)
    initGlobe();

    // Check current state
    const state = await invoke('get_state');
    if (state.status === 'Connected') {
      updateUI('connected');
    } else {
      updateUI('disconnected');
    }

    // Start state sync
    stateCheckInterval = setInterval(checkState, 3000);

  } catch (e) {
    console.error('Init failed:', e);
    // Still init globe for new server setup
    initGlobe();
    updateUI('disconnected');
  }
}

function initGlobe() {
  if (!globeContainer || !window.ParticleGlobe || globe) return;

  try {
    globe = new window.ParticleGlobe(globeContainer);
    console.log('Canvas particle globe initialized');

    // Use ResizeObserver to handle container size changes
    const resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 50 && entry.contentRect.height > 50) {
          globe.resize();
        }
      }
    });
    resizeObserver.observe(globeContainer);

    // Also resize when globe-card becomes visible (hide-globe class removed)
    const mutationObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
          const hasHideClass = globeCard.classList.contains('hide-globe');
          if (!hasHideClass) {
            // Globe became visible - resize after CSS transition completes
            setTimeout(() => globe.resize(), 450);
          }
        }
      }
    });
    mutationObserver.observe(globeCard, { attributes: true });

  } catch (e) {
    console.warn('Failed to initialize particle globe:', e);
  }
}

function initRippleEffect() {
  mainBtn.addEventListener('click', function(e) {
    const rect = this.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const ripple = document.createElement('span');
    ripple.className = 'ripple';
    ripple.style.left = `${x}px`;
    ripple.style.top = `${y}px`;

    this.appendChild(ripple);

    setTimeout(() => ripple.remove(), 600);
  });
}

document.addEventListener('DOMContentLoaded', init);
