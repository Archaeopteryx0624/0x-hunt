#!/usr/bin/env node
// hunt.js - Node.js implementation (reference)

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, existsSync, appendFileSync, unlinkSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { randomUUID } from 'crypto';
import { spawn } from 'child_process';
import { createInterface } from 'readline';
import Groq from 'groq-sdk';
import { fileURLToPath } from 'url';
import os from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// 1. Constants & Config
// ============================================================
const VERSION = '2.0.0';
const SESSION_DIR = resolve(__dirname, 'sessions');
const LOG_DIR = resolve(__dirname, 'logs');
const WORKSPACE_DIR = resolve(__dirname, 'workspace');
const KEY_FILE = resolve(__dirname, '.groq_key');
const MAX_MESSAGES = 200;
const CONTEXT_WINDOW = 60;
const MAX_ITERATIONS = 150;
const AGENT_TIMEOUT = 120000;
const SHELL_TIMEOUT = 300000;
const STDOUT_CAP = 20000;
const STDERR_CAP = 4000;
const INTER_TURN_SLEEP = 600;

const BLOCKED_COMMANDS = [
  /rm\s+-rf\s+\/(?!\w)/,
  /:\(\)\{.*\}/,
  /mkfs/,
  /shutdown\b/,
  /reboot\b/,
  /\bpoweroff\b/
];

const TOOLS = [
  'subfinder', 'assetfinder', 'waybackurls', 'gau', 'katana',
  'hakrawler', 'dig', 'whois', 'nmap', 'httpx', 'nuclei',
  'nikto', 'whatweb', 'ffuf', 'gobuster', 'arjun', 'dalfox',
  'sqlmap', 'gf', 'qsreplace', 'curl', 'wget', 'python3',
  'jq', 'git', 'go'
];

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  
  black: '\x1b[30m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  
  brightBlack: '\x1b[90m',
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightBlue: '\x1b[94m',
  brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
  brightWhite: '\x1b[97m',
  
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
  bgMagenta: '\x1b[45m',
  bgCyan: '\x1b[46m',
};

const SEVERITY_COLORS = {
  'critical': `${COLORS.brightRed}${COLORS.bold}`,
  'high': COLORS.brightRed,
  'medium': COLORS.brightYellow,
  'low': COLORS.brightGreen,
  'informational': COLORS.brightCyan,
};

const SYSTEM_PROMPT = `You are 0x-Hunt, an autonomous bug bounty agent. Your goal is to systematically discover security vulnerabilities within the given scope.

**RESPONSE FORMAT - Follow this structure every turn:**

**PHASE:** [recon|enumerate|scan|fuzz|exploit|report]

**THINK:** [max 3 sentences explaining your reasoning]

**COMMAND:**
\`\`\`bash
<ONE non-interactive command>
\`\`\`

**EXPECT:** [what you expect to see in the output]

**Special blocks you can emit:**

**🚨 FINDING:**
- Type: [vulnerability type]
- Severity: [critical|high|medium|low|informational]
- URL/Asset: [affected asset]
- Parameter: [if applicable]
- Payload: [if applicable]
- Evidence: [supporting evidence]
- Impact: [potential impact]
- Remediation: [how to fix]

**⏸ NEEDS INPUT:**
[Explain what information you need from the operator]

**📋 PHASE COMPLETE: [PHASE]**

**RULES:**
- ONE command per response
- Never touch out-of-scope assets
- No interactive commands (vim, interactive sqlmap, etc.)
- Pipe output through 'tee' to persist findings
- Use non-interactive flags (--batch, --non-interactive, -n, --quiet)
- Stay within scope defined below
- Maximum 150 iterations total`;

// ============================================================
// 2. State & Session Management
// ============================================================
let state = {
  sessions: [],
  currentSessionId: null,
  activeTab: 'log',
  input: '',
  cursorPos: 0,
  history: [],
  historyIdx: 0,
  logScroll: 0,
  showHelp: false,
  status: 'idle',
  statusMsg: '',
  isRunning: false,
  stopRequested: false,
};

let session = null;
let groqClient = null;
let isRawMode = false;
let needsResume = false;

function createSession(target, scope, notes = '') {
  const id = randomUUID();
  const now = new Date().toISOString();
  return {
    id,
    target,
    scope: scope.split('\n').filter(s => s.trim()),
    notes,
    status: 'active',
    phase: 'recon',
    created: now,
    updated: now,
    messages: [],
    findings: [],
    commandHistory: [],
    loopIteration: 0,
  };
}

function saveSession(s) {
  if (!s) return;
  const sess = { ...s };
  // Cap messages to MAX_MESSAGES
  if (sess.messages.length > MAX_MESSAGES) {
    sess.messages = sess.messages.slice(-MAX_MESSAGES);
  }
  sess.updated = new Date().toISOString();
  const path = join(SESSION_DIR, `${sess.id}.json`);
  writeFileSync(path, JSON.stringify(sess, null, 2));
  session = sess;
}

function loadSession(id) {
  const path = join(SESSION_DIR, `${id}.json`);
  if (!existsSync(path)) return null;
  const data = JSON.parse(readFileSync(path, 'utf8'));
  session = data;
  session.messages = session.messages || [];
  session.findings = session.findings || [];
  session.commandHistory = session.commandHistory || [];
  state.currentSessionId = session.id;
  state.status = session.status || 'active';
  return session;
}

function listSessions() {
  if (!existsSync(SESSION_DIR)) return [];
  return readdirSync(SESSION_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      try {
        const data = JSON.parse(readFileSync(join(SESSION_DIR, f), 'utf8'));
        return {
          id: data.id,
          target: data.target || 'unknown',
          phase: data.phase || 'recon',
          findings: data.findings?.length || 0,
          status: data.status || 'active',
          updated: data.updated || data.created || '',
        };
      } catch { return null; }
    })
    .filter(Boolean)
    .sort((a, b) => b.updated.localeCompare(a.updated));
}

function deleteSession(id) {
  const path = join(SESSION_DIR, `${id}.json`);
  if (existsSync(path)) {
    const wsPath = join(WORKSPACE_DIR, id);
    if (existsSync(wsPath)) {
      spawn('rm', ['-rf', wsPath]);
    }
    unlinkSync(path);
    return true;
  }
  return false;
}

function getWorkspaceDir(sessionId) {
  return join(WORKSPACE_DIR, sessionId);
}

function ensureDirs() {
  [SESSION_DIR, LOG_DIR, WORKSPACE_DIR].forEach(d => {
    if (!existsSync(d)) mkdirSync(d, { recursive: true });
  });
}

// ============================================================
// 3. Logging
// ============================================================
function getLogPath(sessionId) {
  return join(LOG_DIR, `${sessionId}.log`);
}

function logToFile(sessionId, text) {
  try {
    const path = getLogPath(sessionId);
    appendFileSync(path, text + '\n');
  } catch {}
}

function logCrash(error) {
  try {
    const path = join(LOG_DIR, 'crash.log');
    const ts = new Date().toISOString();
    appendFileSync(path, `\n[${ts}] ${error.stack || error}\n`);
  } catch {}
}

// ============================================================
// 4. Terminal & ANSI
// ============================================================
const CLEAR = '\x1b[2J\x1b[H';
const HIDE_CURSOR = '\x1b[?25l';
const SHOW_CURSOR = '\x1b[?25h';
const SAVE_CURSOR = '\x1b[s';
const RESTORE_CURSOR = '\x1b[u';

function write(str) {
  process.stdout.write(str);
}

function render() {
  if (state.showHelp) {
    renderHelp();
    return;
  }
  
  write(CLEAR + HIDE_CURSOR);
  renderHeader();
  renderTabs();
  renderContent();
  renderStatusBar();
  renderPrompt();
}

function renderHeader() {
  const target = session?.target || 'no session';
  const status = session?.status || 'idle';
  const statusColor = status === 'active' ? COLORS.green : 
                      status === 'error' ? COLORS.red : 
                      status === 'waiting_input' ? COLORS.yellow : COLORS.dim;
  const isHunting = state.isRunning ? '⚡HUNTING' : 'IDLE';
  
  write(`${COLORS.bold}0x-HUNT v${VERSION}${COLORS.reset}`);
  write(`  ${COLORS.cyan}${target}${COLORS.reset}`);
  write(`  ${statusColor}[${status.toUpperCase()}]${COLORS.reset}`);
  write(`  ${COLORS.brightYellow}${isHunting}${COLORS.reset}`);
  write(`  ${COLORS.dim}${getRamUsage()} ${getCpuUsage()}${COLORS.reset}`);
  write('\n');
}

function renderTabs() {
  const tabs = ['LOG', 'FINDINGS', 'SHELL', 'FILES', 'SESSIONS'];
  const keys = ['L', 'F', 'S', 'X', 'E'];
  let line = ' ';
  tabs.forEach((tab, i) => {
    const isActive = state.activeTab === tab.toLowerCase();
    const key = keys[i];
    if (isActive) {
      line += `${COLORS.bgBlue}${COLORS.white} ${key}]${tab} ${COLORS.reset}`;
    } else {
      line += `${COLORS.dim}[${key}]${tab}${COLORS.reset}`;
    }
    if (i < tabs.length - 1) line += ' ';
  });
  write(line + '\n');
}

function renderContent() {
  const cols = process.stdout.columns || 80;
  write('─'.repeat(Math.max(0, cols)) + '\n');
  
  switch (state.activeTab) {
    case 'log':
      renderLog();
      break;
    case 'findings':
      renderFindings();
      break;
    case 'shell':
      renderShell();
      break;
    case 'files':
      renderFiles();
      break;
    case 'sessions':
      renderSessions();
      break;
  }
  
  write('─'.repeat(Math.max(0, cols)) + '\n');
}

function renderLog() {
  if (!session) {
    write(`${COLORS.dim}No session active. Create or load one.${COLORS.reset}\n`);
    return;
  }
  
  const lines = [];
  // Build log from messages, findings, command history
  session.messages.forEach(msg => {
    const role = msg.role === 'assistant' ? '🤖' : '👤';
    const content = msg.content.length > 500 ? msg.content.substring(0, 500) + '...' : msg.content;
    lines.push(`${COLORS.cyan}${role} ${content}${COLORS.reset}`);
  });
  
  session.findings.forEach(f => {
    const color = SEVERITY_COLORS[f.severity?.toLowerCase()] || COLORS.white;
    lines.push(`${COLORS.brightRed}🚨 ${color}${f.text}${COLORS.reset}`);
  });
  
  session.commandHistory.slice(-20).forEach(cmd => {
    const icon = cmd.exitCode === 0 ? '✅' : '❌';
    lines.push(`${COLORS.dim}${icon} $ ${cmd.cmd}${COLORS.reset}`);
    if (cmd.stdout) {
      const out = cmd.stdout.substring(0, 200);
      lines.push(`${COLORS.dim}  ${out}${COLORS.reset}`);
    }
    if (cmd.stderr) {
      const err = cmd.stderr.substring(0, 200);
      lines.push(`${COLORS.red}  ${err}${COLORS.reset}`);
    }
  });
  
  const height = Math.max(0, (process.stdout.rows || 24) - 12);
  const start = Math.max(0, lines.length - height + state.logScroll);
  const end = Math.min(lines.length, start + height);
  
  for (let i = start; i < end; i++) {
    write(lines[i] + '\n');
  }
}

function renderFindings() {
  if (!session || !session.findings.length) {
    write(`${COLORS.dim}No findings yet.${COLORS.reset}\n`);
    return;
  }
  
  session.findings.forEach((f, i) => {
    const color = SEVERITY_COLORS[f.severity?.toLowerCase()] || COLORS.white;
    const prefix = f.severity?.toUpperCase() || 'INFO';
    write(`${i+1}. ${color}[${prefix}] ${f.text.substring(0, 80)}${COLORS.reset}\n`);
  });
}

function renderShell() {
  if (!session) {
    write(`${COLORS.dim}No session active.${COLORS.reset}\n`);
    return;
  }
  write(`${COLORS.dim}Shell mode active. Commands run in workspace.${COLORS.reset}\n`);
  write(`${COLORS.dim}Workspace: ${getWorkspaceDir(session.id)}${COLORS.reset}\n`);
  write(`${COLORS.dim}Type commands directly or use !command from any tab${COLORS.reset}\n`);
}

function renderFiles() {
  if (!session) {
    write(`${COLORS.dim}No session active.${COLORS.reset}\n`);
    return;
  }
  const ws = getWorkspaceDir(session.id);
  if (!existsSync(ws)) {
    write(`${COLORS.dim}Workspace empty.${COLORS.reset}\n`);
    return;
  }
  try {
    const files = readdirSync(ws);
    if (!files.length) {
      write(`${COLORS.dim}Workspace empty.${COLORS.reset}\n`);
      return;
    }
    files.forEach(f => {
      const st = statSync(join(ws, f));
      const type = st.isDirectory() ? '📁' : '📄';
      const size = (st.size / 1024).toFixed(1);
      write(`${type} ${f} ${COLORS.dim}${size}KB${COLORS.reset}\n`);
    });
  } catch (e) {
    write(`${COLORS.red}Error reading workspace: ${e.message}${COLORS.reset}\n`);
  }
}

function renderSessions() {
  const sessions = listSessions();
  if (!sessions.length) {
    write(`${COLORS.dim}No saved sessions.${COLORS.reset}\n`);
    write(`${COLORS.dim}Use :new to create one.${COLORS.reset}\n`);
    return;
  }
  sessions.forEach((s, i) => {
    const active = s.id === state.currentSessionId ? '▶ ' : '  ';
    const statusColor = s.status === 'active' ? COLORS.green : 
                        s.status === 'error' ? COLORS.red : 
                        s.status === 'waiting_input' ? COLORS.yellow : COLORS.dim;
    write(`${active}${i+1}. ${COLORS.cyan}${s.target}${COLORS.reset} ${statusColor}${s.status}${COLORS.reset} ${s.findings} findings ${COLORS.dim}${s.phase}${COLORS.reset}\n`);
  });
  write(`${COLORS.dim}Use :load <id> to load a session${COLORS.reset}\n`);
}

function renderStatusBar() {
  const findings = session?.findings?.length || 0;
  const commands = session?.commandHistory?.length || 0;
  const iter = session?.loopIteration || 0;
  const ram = getRamUsage();
  const cols = process.stdout.columns || 80;
  
  const left = `finds:${findings}  cmds:${commands}  iter:${iter}  ${ram}`;
  write(left);
  
  // Simple progress bar
  const pct = Math.min(100, (iter / MAX_ITERATIONS) * 100);
  const barLen = Math.max(0, Math.min(20, cols - left.length - 10));
  const filled = Math.floor((pct / 100) * barLen);
  const bar = '█'.repeat(Math.max(0, filled)) + '░'.repeat(Math.max(0, barLen - filled));
  const color = pct > 90 ? COLORS.red : pct > 70 ? COLORS.yellow : COLORS.green;
  write(`  ${color}${bar}${COLORS.reset} ${Math.floor(pct)}%\n`);
}

function renderPrompt() {
  const prompt = session ? `${COLORS.green}0x>${COLORS.reset} ` : `${COLORS.dim}0x>${COLORS.reset} `;
  write(`${prompt}${state.input}\x1b[${state.cursorPos + prompt.length + 1}G`);
}

function renderHelp() {
  write(CLEAR + HIDE_CURSOR);
  write(`${COLORS.bold}0x-HUNT v${VERSION} — Help${COLORS.reset}\n\n`);
  write(`${COLORS.cyan}Tabs:${COLORS.reset}\n`);
  write(`  :log/l   :findings/f   :shell/s   :files/x   :sessions/e\n\n`);
  write(`${COLORS.cyan}Commands:${COLORS.reset}\n`);
  write(`  :load <id>   Load session\n`);
  write(`  :new         Create new session\n`);
  write(`  :del <id>    Delete session\n`);
  write(`  :stop        Stop running agent\n`);
  write(`  :go/:continue Resume agent\n`);
  write(`  :report      Generate report\n`);
  write(`  :key         Set Groq API key\n`);
  write(`  :status      Show session status\n`);
  write(`  :ls          List sessions\n`);
  write(`  :clearlog    Clear log\n`);
  write(`  :ram/:cpu/:disk/:net/:tools System info\n`);
  write(`  :groqtest    Test API key\n`);
  write(`  :help/?      Show this help\n`);
  write(`  :q/:quit     Exit\n\n`);
  write(`${COLORS.cyan}Navigation:${COLORS.reset}\n`);
  write(`  Tab          Cycle tabs\n`);
  write(`  j/k          Scroll log\n`);
  write(`  g/G          Top/bottom\n`);
  write(`  Ctrl+L       Clear log\n`);
  write(`  Ctrl+C       Stop/exit\n\n`);
  write(`${COLORS.dim}Press any key to return...${COLORS.reset}`);
}

// ============================================================
// 5. System Info
// ============================================================
function getRamUsage() {
  try {
    const mem = process.memoryUsage();
    const used = (mem.heapUsed / 1024 / 1024).toFixed(1);
    const total = (mem.heapTotal / 1024 / 1024).toFixed(1);
    return `${used}M/${total}M`;
  } catch {
    return '?/?';
  }
}

function getCpuUsage() {
  try {
    const cpus = os.cpus();
    return `${cpus.length} cores`;
  } catch {
    return '? cores';
  }
}

function getSystemInfo() {
  const load = os.loadavg();
  const totalMem = (os.totalmem() / 1024 / 1024 / 1024).toFixed(1);
  const freeMem = (os.freemem() / 1024 / 1024 / 1024).toFixed(1);
  return {
    cpu: os.cpus().length,
    load: load.map(l => l.toFixed(2)),
    ram: `${freeMem}G/${totalMem}G`,
    platform: os.platform(),
    arch: os.arch(),
  };
}

function checkVPN() {
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (/^(tun|tap|wg|vpn|ppp)/.test(name)) {
      for (const addr of addrs || []) {
        if (!addr.internal && addr.family === 'IPv4') {
          return `${name}: ${addr.address}`;
        }
      }
    }
  }
  return 'none';
}

// ============================================================
// 6. Input Handling
// ============================================================
function setupInput() {
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  isRawMode = true;
  process.stdin.on('data', chunk => handleInput(chunk));
}

function handleInput(chunk) {
  if (state.showHelp) {
    state.showHelp = false;
    render();
    return;
  }
  
  // Escape sequences
  if (chunk === '\x1b[A') { // Up
    if (state.history.length > 0) {
      state.historyIdx = Math.max(0, state.historyIdx - 1);
      state.input = state.history[state.historyIdx] || '';
      state.cursorPos = state.input.length;
      render();
    }
    return;
  }
  if (chunk === '\x1b[B') { // Down
    if (state.history.length > 0) {
      state.historyIdx = Math.min(state.history.length - 1, state.historyIdx + 1);
      state.input = state.history[state.historyIdx] || '';
      state.cursorPos = state.input.length;
      render();
    }
    return;
  }
  if (chunk === '\x1b[C') { // Right
    state.cursorPos = Math.min(state.input.length, state.cursorPos + 1);
    render();
    return;
  }
  if (chunk === '\x1b[D') { // Left
    state.cursorPos = Math.max(0, state.cursorPos - 1);
    render();
    return;
  }
  
  // Control sequences
  if (chunk === '\x03') { // Ctrl+C
    if (state.isRunning) {
      state.stopRequested = true;
      state.statusMsg = 'Stopping agent...';
      render();
    } else {
      cleanExit();
    }
    return;
  }
  if (chunk === '\x0c') { // Ctrl+L
    if (session) {
      session.messages = [];
      saveSession(session);
    }
    render();
    return;
  }
  if (chunk === '\x15') { // Ctrl+U
    state.input = '';
    state.cursorPos = 0;
    render();
    return;
  }
  if (chunk === '\x09') { // Tab
    const tabs = ['log', 'findings', 'shell', 'files', 'sessions'];
    const idx = tabs.indexOf(state.activeTab);
    state.activeTab = tabs[(idx + 1) % tabs.length];
    render();
    return;
  }
  if (chunk === '\x7f' || chunk === '\x08') { // Backspace
    if (state.cursorPos > 0) {
      state.input = state.input.slice(0, state.cursorPos - 1) + state.input.slice(state.cursorPos);
      state.cursorPos--;
      render();
    }
    return;
  }
  if (chunk === '\r' || chunk === '\n') { // Enter
    if (state.input.trim()) {
      state.history.push(state.input);
      state.historyIdx = state.history.length;
      const cmd = state.input.trim();
      state.input = '';
      state.cursorPos = 0;
      handleCommand(cmd);
    }
    render();
    return;
  }
  
  // Printable characters
  if (chunk >= ' ') {
    state.input = state.input.slice(0, state.cursorPos) + chunk + state.input.slice(state.cursorPos);
    state.cursorPos++;
    render();
  }
}

// ============================================================
// 7. Command Router
// ============================================================
async function handleCommand(cmd) {
  const parts = cmd.trim().split(/\s+/);
  const main = parts[0].toLowerCase();
  
  // Tab switches
  if ([':log', 'l'].includes(main)) { state.activeTab = 'log'; render(); return; }
  if ([':findings', 'f'].includes(main)) { state.activeTab = 'findings'; render(); return; }
  if ([':shell', 's'].includes(main)) { state.activeTab = 'shell'; render(); return; }
  if ([':files', 'x'].includes(main)) { state.activeTab = 'files'; render(); return; }
  if ([':sessions', 'e'].includes(main)) { state.activeTab = 'sessions'; render(); return; }
  
  // Scrolling
  if (main === 'j' || main === ':down') { state.logScroll++; render(); return; }
  if (main === 'k' || main === ':up') { state.logScroll = Math.max(0, state.logScroll - 1); render(); return; }
  if (main === 'g' || main === ':top') { state.logScroll = 0; render(); return; }
  if (main === 'G' || main === ':bot') { state.logScroll = 9999; render(); return; }
  
  // Help
  if ([':help', ':h', '?'].includes(main)) {
    state.showHelp = true;
    render();
    return;
  }
  
  // Quit
  if ([':q', ':quit', ':exit'].includes(main)) {
    cleanExit();
    return;
  }
  
  // System info
  if (main === ':ram') {
    const info = getSystemInfo();
    state.statusMsg = `RAM: ${info.ram}`;
    render();
    return;
  }
  if (main === ':cpu') {
    const info = getSystemInfo();
    state.statusMsg = `CPU: ${info.cpu} cores, load: ${info.load.join(', ')}`;
    render();
    return;
  }
  if (main === ':disk') {
    try {
      const result = await execCommand('df -h /');
      state.statusMsg = `Disk:\n${result.stdout}`;
    } catch { state.statusMsg = 'Disk info failed'; }
    render();
    return;
  }
  if (main === ':net') {
    const vpn = checkVPN();
    state.statusMsg = `VPN: ${vpn}`;
    render();
    return;
  }
  if (main === ':tools') {
    const found = TOOLS.filter(t => {
      try { 
        const result = spawn('command', ['-v', t]);
        return result.status === 0;
      } catch { return false; }
    });
    state.statusMsg = `Tools: ${found.join(', ') || 'none found'}`;
    render();
    return;
  }
  if (main === ':status') {
    if (!session) { state.statusMsg = 'No active session'; render(); return; }
    state.statusMsg = `Session: ${session.target} | Phase: ${session.phase} | Iter: ${session.loopIteration} | Findings: ${session.findings.length}`;
    render();
    return;
  }
  if (main === ':groqtest') {
    if (!groqClient) { state.statusMsg = 'No API key configured'; render(); return; }
    try {
      await groqClient.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: 'Hello' }],
        max_tokens: 10,
      });
      state.statusMsg = '✅ Groq API test passed!';
    } catch (e) {
      state.statusMsg = `❌ Groq API test failed: ${e.message}`;
    }
    render();
    return;
  }
  
  // Session management
  if (main === ':ls') {
    const sessions = listSessions();
    state.statusMsg = sessions.length ? `Found ${sessions.length} sessions` : 'No sessions found';
    render();
    return;
  }
  
  if (main === ':load') {
    if (parts.length < 2) {
      state.statusMsg = 'Usage: :load <session-id>';
      render();
      return;
    }
    const id = parts[1];
    if (loadSession(id)) {
      state.statusMsg = `Loaded session: ${session.target}`;
      render();
      if (session.status === 'active') {
        state.isRunning = true;
        runAgentLoop();
      }
    } else {
      state.statusMsg = `Session not found: ${id}`;
      render();
    }
    return;
  }
  
  if (main === ':new') {
    await promptNewSession();
    render();
    return;
  }
  
  if (main === ':del') {
    if (parts.length < 2) {
      state.statusMsg = 'Usage: :del <session-id>';
      render();
      return;
    }
    const id = parts[1];
    // Confirm via prompt
    const confirm = await promptConfirm(`Delete session ${id}? (y/N) `);
    if (confirm) {
      if (deleteSession(id)) {
        if (state.currentSessionId === id) {
          state.currentSessionId = null;
          session = null;
        }
        state.statusMsg = `Deleted session: ${id}`;
      } else {
        state.statusMsg = `Failed to delete: ${id}`;
      }
    } else {
      state.statusMsg = 'Cancelled';
    }
    render();
    return;
  }
  
  if (main === ':stop') {
    if (state.isRunning) {
      state.stopRequested = true;
      state.statusMsg = 'Stopping agent...';
    } else {
      state.statusMsg = 'Agent not running';
    }
    render();
    return;
  }
  
  if ([':go', ':continue', ':cont'].includes(main)) {
    if (!session) {
      state.statusMsg = 'No session active';
      render();
      return;
    }
    if (state.isRunning) {
      state.statusMsg = 'Agent already running';
      render();
      return;
    }
    state.isRunning = true;
    state.stopRequested = false;
    session.status = 'active';
    saveSession(session);
    render();
    runAgentLoop();
    return;
  }
  
  if (main === ':report') {
    if (!session) {
      state.statusMsg = 'No session active';
      render();
      return;
    }
    generateReport();
    render();
    return;
  }
  
  if (main === ':clearlog') {
    if (session) {
      session.messages = [];
      saveSession(session);
      state.statusMsg = 'Log cleared';
    }
    render();
    return;
  }
  
  if (main === ':key') {
    if (parts.length >= 2 && parts[1].startsWith('gsk_')) {
      setApiKey(parts[1]);
    } else {
      const key = await promptInput('Enter Groq API key (gsk_...): ');
      if (key) setApiKey(key);
    }
    render();
    return;
  }
  
  // Shell passthrough
  if (state.activeTab === 'shell' || cmd.startsWith('!')) {
    const shellCmd = cmd.startsWith('!') ? cmd.slice(1).trim() : cmd.trim();
    if (!session) {
      state.statusMsg = 'No session active';
      render();
      return;
    }
    await executeShellCommand(shellCmd, SHELL_TIMEOUT);
    render();
    return;
  }
  
  // Send message to agent
  if (session && !cmd.startsWith(':')) {
    sendUserMessage(cmd);
    return;
  }
  
  state.statusMsg = `Unknown command: ${cmd}`;
  render();
}

// ============================================================
// 8. Prompt Helpers (with safe raw mode handling)
// ============================================================
function withRawRestore(fn) {
  return async function(...args) {
    // Disable raw mode for user input
    if (isRawMode) {
      process.stdin.setRawMode(false);
      isRawMode = false;
    }
    try {
      const result = await fn(...args);
      return result;
    } finally {
      // Re-enable raw mode
      if (!isRawMode) {
        process.stdin.setRawMode(true);
        process.stdin.resume(); // Critical: resume after readline close
        isRawMode = true;
      }
    }
  };
}

const promptInput = withRawRestore((prompt) => {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
});

const promptConfirm = withRawRestore((prompt) => {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(/^y/i.test(answer.trim()));
    });
  });
});

async function promptNewSession() {
  const target = await promptInput('Target domain: ');
  if (!target) { state.statusMsg = 'Cancelled'; return; }
  
  const scope = await promptInput('Scope (comma-separated domains): ');
  if (!scope) { state.statusMsg = 'Cancelled'; return; }
  
  const notes = await promptInput('Notes (optional): ');
  
  const s = createSession(target, scope.replace(/,/g, '\n'), notes);
  session = s;
  state.currentSessionId = s.id;
  saveSession(s);
  state.statusMsg = `Created session: ${target}`;
  state.isRunning = true;
  state.stopRequested = false;
  runAgentLoop();
}

function setApiKey(key) {
  try {
    writeFileSync(KEY_FILE, key.trim(), { mode: 0o600 });
    state.statusMsg = '✅ API key saved';
    initGroqClient();
  } catch (e) {
    state.statusMsg = `❌ Failed to save key: ${e.message}`;
  }
}

function loadApiKey() {
  try {
    if (existsSync(KEY_FILE)) {
      const key = readFileSync(KEY_FILE, 'utf8').trim();
      if (key.startsWith('gsk_')) {
        return key;
      }
    }
  } catch {}
  return null;
}

function initGroqClient() {
  const key = loadApiKey();
  if (!key) return null;
  try {
    groqClient = new Groq({ apiKey: key });
    return groqClient;
  } catch {
    return null;
  }
}

// ============================================================
// 9. Command Execution
// ============================================================
function isCommandBlocked(cmd) {
  return BLOCKED_COMMANDS.some(pattern => pattern.test(cmd));
}

function execCommand(cmd, cwd, timeout = AGENT_TIMEOUT) {
  return new Promise((resolve, reject) => {
    if (isCommandBlocked(cmd)) {
      return reject(new Error('⛔ BLOCKED: Command matches blocked pattern'));
    }
    
    const child = spawn('bash', ['-c', cmd], {
      cwd: cwd || process.cwd(),
      env: {
        ...process.env,
        PATH: `${process.env.PATH}:/root/go/bin:${process.env.HOME}/go/bin:/usr/local/bin:${process.env.HOME}/.local/bin`,
        TERM: 'xterm-256color',
      },
    });
    
    let stdout = '';
    let stderr = '';
    let truncated = false;
    
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error('Command timed out'));
    }, timeout);
    
    child.stdout.on('data', (data) => {
      const chunk = data.toString();
      if (stdout.length + chunk.length > STDOUT_CAP) {
        stdout += chunk.slice(0, STDOUT_CAP - stdout.length);
        truncated = true;
        child.stdout.destroy();
      } else {
        stdout += chunk;
      }
    });
    
    child.stderr.on('data', (data) => {
      const chunk = data.toString();
      if (stderr.length + chunk.length > STDERR_CAP) {
        stderr += chunk.slice(0, STDERR_CAP - stderr.length);
        truncated = true;
        child.stderr.destroy();
      } else {
        stderr += chunk;
      }
    });
    
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        stdout: stdout.slice(0, STDOUT_CAP),
        stderr: stderr.slice(0, STDERR_CAP),
        exitCode: code,
        truncated,
        cmd,
      });
    });
    
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function executeShellCommand(cmd, timeout = SHELL_TIMEOUT) {
  if (!session) return;
  
  const ws = getWorkspaceDir(session.id);
  if (!existsSync(ws)) mkdirSync(ws, { recursive: true });
  
  try {
    const result = await execCommand(cmd, ws, timeout);
    const entry = {
      id: randomUUID(),
      cmd,
      ts: new Date().toISOString(),
      phase: session.phase,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
    };
    session.commandHistory.push(entry);
    logToFile(session.id, `$ ${cmd}\n${result.stdout}\n${result.stderr}\nExit: ${result.exitCode}`);
    saveSession(session);
    state.statusMsg = `Command exited with code ${result.exitCode}`;
  } catch (e) {
    state.statusMsg = e.message;
    logToFile(session.id, `$ ${cmd}\nError: ${e.message}`);
  }
}

// ============================================================
// 10. Agent Loop
// ============================================================
async function runAgentLoop() {
  if (!session) return;
  if (!groqClient) {
    groqClient = initGroqClient();
    if (!groqClient) {
      state.statusMsg = 'No Groq API key configured. Use :key';
      state.isRunning = false;
      render();
      return;
    }
  }
  
  state.isRunning = true;
  state.stopRequested = false;
  session.status = 'active';
  saveSession(session);
  
  while (state.isRunning && !state.stopRequested && session.loopIteration < MAX_ITERATIONS) {
    const result = await runAgentTurn();
    
    if (result?.needsInput) {
      state.isRunning = false;
      session.status = 'waiting_input';
      saveSession(session);
      render();
      return;
    }
    
    if (result?.error) {
      state.isRunning = false;
      session.status = 'error';
      saveSession(session);
      render();
      return;
    }
    
    session.loopIteration++;
    saveSession(session);
    render();
    
    await sleep(INTER_TURN_SLEEP);
  }
  
  if (session.loopIteration >= MAX_ITERATIONS) {
    session.status = 'active';
    state.statusMsg = 'Iteration cap reached (150)';
    state.isRunning = false;
    saveSession(session);
  }
  
  state.isRunning = false;
  render();
}

async function runAgentTurn() {
  if (!session) return { error: 'No session' };
  if (!groqClient) return { error: 'No Groq client' };
  
  // Build context
  const messages = [];
  
  // System prompt
  messages.push({ role: 'system', content: SYSTEM_PROMPT });
  
  // Context header
  const scopeText = session.scope.join('\n');
  const header = `TARGET: ${session.target}\nSCOPE:\n${scopeText}\nNOTES: ${session.notes || 'none'}\nPHASE: ${session.phase}\nITERATION: ${session.loopIteration + 1}/${MAX_ITERATIONS}`;
  messages.push({ role: 'user', content: header });
  
  // Last N messages
  const history = session.messages.slice(-CONTEXT_WINDOW);
  messages.push(...history);
  
  try {
    const response = await groqClient.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages,
      temperature: 0.15,
      max_tokens: 2048,
    });
    
    const content = response.choices[0].message.content;
    session.messages.push({ role: 'assistant', content });
    logToFile(session.id, `🤖 ${content}`);
    
    // Parse response
    await parseAgentResponse(content);
    saveSession(session);
    return { success: true };
    
  } catch (e) {
    logToFile(session.id, `❌ Agent error: ${e.message}`);
    return { error: e.message };
  }
}

async function parseAgentResponse(content) {
  // Extract PHASE
  const phaseMatch = content.match(/\*\*PHASE:\*\*\s*(\w+)/);
  if (phaseMatch) {
    const phase = phaseMatch[1].toLowerCase();
    if (['recon', 'enumerate', 'scan', 'fuzz', 'exploit', 'report'].includes(phase)) {
      session.phase = phase;
      logToFile(session.id, `📋 Phase: ${phase}`);
    }
  }
  
  // Extract FINDING
  const findingMatch = content.match(/\*\*🚨 FINDING:\*\*([\s\S]*?)(?=\*\*|$)/);
  if (findingMatch) {
    const findingText = findingMatch[1].trim();
    const severityMatch = findingText.match(/- Severity:\s*(\w+)/);
    const severity = severityMatch ? severityMatch[1].toLowerCase() : 'informational';
    session.findings.push({
      id: randomUUID(),
      text: findingText,
      timestamp: new Date().toISOString(),
      phase: session.phase,
      severity,
    });
    logToFile(session.id, `🚨 FINDING: ${findingText.substring(0, 100)}...`);
  }
  
  // Extract NEEDS INPUT
  const inputMatch = content.match(/\*\*⏸ NEEDS INPUT:\*\*([\s\S]*?)(?=\*\*|$)/);
  if (inputMatch) {
    session.status = 'waiting_input';
    logToFile(session.id, `⏸ Needs input: ${inputMatch[1].trim()}`);
    return { needsInput: true };
  }
  
  // Extract COMMAND
  const cmdMatch = content.match(/```bash\n([\s\S]*?)```/);
  if (cmdMatch) {
    const cmd = cmdMatch[1].trim();
    if (cmd && !isCommandBlocked(cmd)) {
      logToFile(session.id, `$ ${cmd}`);
      // Execute command
      const ws = getWorkspaceDir(session.id);
      if (!existsSync(ws)) mkdirSync(ws, { recursive: true });
      
      try {
        const result = await execCommand(cmd, ws, AGENT_TIMEOUT);
        const entry = {
          id: randomUUID(),
          cmd,
          ts: new Date().toISOString(),
          phase: session.phase,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
        };
        session.commandHistory.push(entry);
        logToFile(session.id, `Output: ${result.stdout.substring(0, 200)}`);
        // Feed output back as user message
        const feedback = `Command output (exit ${result.exitCode}):\n${result.stdout}\n${result.stderr}`;
        session.messages.push({ role: 'user', content: feedback.substring(0, 4000) });
        saveSession(session);
      } catch (e) {
        logToFile(session.id, `⛔ ${e.message}`);
        session.messages.push({ role: 'user', content: `Error: ${e.message}` });
        saveSession(session);
      }
    } else if (cmd && isCommandBlocked(cmd)) {
      session.messages.push({ role: 'user', content: `⛔ BLOCKED: ${cmd}` });
      logToFile(session.id, `⛔ BLOCKED: ${cmd}`);
    }
  }
  
  // Check for PHASE COMPLETE
  if (content.includes('**📋 PHASE COMPLETE:')) {
    logToFile(session.id, `📋 Phase complete: ${session.phase}`);
  }
}

function sendUserMessage(msg) {
  if (!session) return;
  session.messages.push({ role: 'user', content: msg });
  saveSession(session);
  render();
  if (!state.isRunning && session.status === 'active') {
    state.isRunning = true;
    runAgentLoop();
  }
}

function generateReport() {
  if (!session) return;
  const report = [];
  report.push(`# Bug Bounty Report: ${session.target}`);
  report.push(`\n## Summary`);
  report.push(`- Phase: ${session.phase}`);
  report.push(`- Iterations: ${session.loopIteration}`);
  report.push(`- Findings: ${session.findings.length}`);
  report.push(`- Commands: ${session.commandHistory.length}`);
  report.push(`\n## Scope`);
  session.scope.forEach(s => report.push(`- ${s}`));
  report.push(`\n## Findings`);
  session.findings.forEach((f, i) => {
    report.push(`\n### ${i+1}. ${f.text.substring(0, 60)}...`);
    report.push(`- Severity: ${f.severity || 'unknown'}`);
    report.push(`- Phase: ${f.phase || 'unknown'}`);
  });
  report.push(`\n## Command History`);
  session.commandHistory.slice(-20).forEach(c => {
    report.push(`- $ ${c.cmd} (exit ${c.exitCode})`);
  });
  
  const content = report.join('\n');
  const ws = getWorkspaceDir(session.id);
  if (!existsSync(ws)) mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, 'report.txt'), content);
  state.statusMsg = `Report saved to ${ws}/report.txt`;
  logToFile(session.id, `📋 Report generated`);
}

// ============================================================
// 11. Utilities
// ============================================================
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function cleanExit() {
  if (isRawMode) {
    process.stdin.setRawMode(false);
    isRawMode = false;
  }
  write(SHOW_CURSOR + COLORS.reset + '\n');
  process.exit(0);
}

// ============================================================
// 12. Error Handling
// ============================================================
process.on('uncaughtException', (err) => {
  logCrash(err);
  if (isRawMode) {
    process.stdin.setRawMode(false);
    isRawMode = false;
  }
  write(SHOW_CURSOR + COLORS.reset + '\n');
  console.error('Crash:', err.stack);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  logCrash(err);
  if (isRawMode) {
    process.stdin.setRawMode(false);
    isRawMode = false;
  }
  write(SHOW_CURSOR + COLORS.reset + '\n');
  console.error('Unhandled rejection:', err);
  process.exit(1);
});

process.on('SIGTERM', cleanExit);
process.on('SIGINT', cleanExit);

// ============================================================
// 13. Resize Handling
// ============================================================
process.stdout.on('resize', () => {
  try {
    render();
  } catch (e) {
    // Silently ignore resize errors
  }
});

// ============================================================
// 14. Boot
// ============================================================
async function boot() {
  ensureDirs();
  write(CLEAR + HIDE_CURSOR);
  
  // Banner
  write(`${COLORS.bold}${COLORS.brightRed}
   █████╗  ██╗  ██╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
  ██╔══██╗ ╚██╗██╔╝     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝
  ███████║  ╚███╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   
  ██╔══██║  ██╔██╗╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   
  ██║  ██║ ██╔╝ ██╗     ██║  ██║╚██████╔╝██║ ╚████║   ██║   
  ╚═╝  ╚═╝ ╚═╝  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
  ${COLORS.reset}`);
  write(`${COLORS.bold}0x-HUNT v${VERSION} — Autonomous Bug Bounty Hunter${COLORS.reset}\n\n`);
  
  // System snapshot
  const info = getSystemInfo();
  const vpn = checkVPN();
  const key = loadApiKey();
  write(`${COLORS.cyan}System:${COLORS.reset} ${info.platform} ${info.arch}  ${info.cpu} cores\n`);
  write(`${COLORS.cyan}RAM:${COLORS.reset} ${info.ram}  ${COLORS.cyan}VPN:${COLORS.reset} ${vpn}\n`);
  write(`${COLORS.cyan}Groq key:${COLORS.reset} ${key ? '✅ configured' : '❌ not set'}\n\n`);
  
  // Recent sessions
  const sessions = listSessions().slice(0, 3);
  if (sessions.length) {
    write(`${COLORS.cyan}Recent sessions:${COLORS.reset}\n`);
    sessions.forEach((s, i) => {
      write(`  ${i+1}. ${s.target} ${COLORS.dim}(${s.findings} findings, ${s.phase})${COLORS.reset}\n`);
    });
    write('\n');
  }
  
  write(`${COLORS.dim}Press any key to start...${COLORS.reset}`);
  
  // Wait for key
  await new Promise(resolve => {
    process.stdin.setRawMode(false);
    process.stdin.resume();
    process.stdin.once('data', () => {
      process.stdin.pause();
      resolve();
    });
  });
  
  // Init
  if (key) initGroqClient();
  setupInput();
  render();
  
  // Periodic refresh
  setInterval(() => {
    if (!state.isRunning) render();
  }, 10000);
}

boot();
  inputBuffer   : '',
  inputCursor   : 0,
  promptMode    : 'main',
  multilineKey  : '',
  multilineBuf  : [],
  statusMsg     : '',
  statusColor   : A.gray,
};

const MAX_LOG = 2000;

// ── Logging ───────────────────────────────────────────────────────────────────
function pushLog(line) {
  state.logLines.push(line);
  if (state.logLines.length > MAX_LOG) state.logLines.shift();
}

function logSection(header, color = A.cyan) {
  pushLog('');
  pushLog(c(color, '━'.repeat(Math.min(W()-1, 60))));
  pushLog(c(A.bold + color, '  ' + header));
  pushLog(c(color, '━'.repeat(Math.min(W()-1, 60))));
}

function logAI(text) {
  logSection('0x-HUNT', A.cyan);
  const lines = text.split('\n');
  for (const line of lines) {
    if (/^\*\*PHASE:\*\*/.test(line)) {
      const phase = line.replace(/\*\*PHASE:\*\*\s*/,'').trim();
      pushLog(c(A.bgblue + A.bwhite, ' PHASE ') + ' ' + c(A.bold+A.bcyan, phase));
      if (state.session) { state.session.phase = phase.toLowerCase(); }
    } else if (/^\*\*THINK:\*\*/.test(line)) {
      pushLog(c(A.bmagenta, '  THINK ') + c(A.magenta, line.replace(/\*\*THINK:\*\*\s*/,'')));
    } else if (/^\*\*COMMAND:\*\*/.test(line)) {
      pushLog(c(A.byellow, '  CMD   '));
    } else if (/^\*\*EXPECT:\*\*/.test(line)) {
      pushLog(c(A.gray, '  EXPECT ') + c(A.dim, line.replace(/\*\*EXPECT:\*\*\s*/,'')));
    } else if (/^```/.test(line)) {
      // skip fence markers
    } else if (/^🚨 FINDING:/.test(line)) {
      pushLog(c(A.bgred + A.bwhite + A.bold, ' 🚨 FINDING '));
    } else if (/^- (Type|Severity|URL|Parameter|Payload|Evidence|Impact|Remediation):/.test(line)) {
      const [k,...v] = line.replace(/^- /,'').split(':');
      pushLog('  ' + c(A.byellow, k+':') + c(A.white, v.join(':').trim()));
    } else if (/^⏸ NEEDS INPUT:/.test(line)) {
      pushLog(c(A.bgyellow + A.black + A.bold, ' ⏸ NEEDS INPUT '));
    } else if (/^📋 PHASE COMPLETE:/.test(line)) {
      pushLog(c(A.bggreen + A.black + A.bold, ' 📋 ' + line));
    } else if (/^\*\*/.test(line)) {
      pushLog(c(A.bold+A.white, line.replace(/\*\*/g,'')));
    } else if (line.trim()) {
      pushLog('  ' + c(A.white, line));
    }
  }
}

function logExec(cmd) {
  pushLog('');
  pushLog(c(A.byellow, '▶ ') + c(A.yellow, 'EXEC  ') + c(A.bwhite, cmd));
}

function logResult(result) {
  const exitColor = result.exitCode === 0 ? A.bgreen : A.bred;
  pushLog(c(exitColor, `  EXIT ${result.exitCode}`) + (result.truncated ? c(A.gray,' [truncated]') : ''));
  if (result.stdout.trim()) {
    const lines = result.stdout.trim().split('\n');
    const show = lines.slice(0, 60);
    show.forEach(l => pushLog(c(A.gray, '  │ ') + l));
    if (lines.length > 60) pushLog(c(A.gray, `  │ … ${lines.length - 60} more lines (see shell tab)`));
  }
  if (result.stderr.trim()) {
    result.stderr.trim().split('\n').slice(0, 10).forEach(l => pushLog(c(A.red, '  ! ') + l));
  }
}

function logSys(text, color = A.gray) {
  pushLog(c(color, '  ⟫ ') + c(color, text));
}

function logFinding(text) {
  pushLog('');
  const lines = text.split('\n');
  lines.forEach(l => {
    if (/^🚨 FINDING:/.test(l)) pushLog(c(A.bgred + A.bwhite + A.bold, ' 🚨 FINDING '));
    else if (/^- Severity:/.test(l)) {
      const sev = l.split(':')[1]?.trim();
      const sevColor = {Critical:A.bred,High:A.bred,Medium:A.byellow,Low:A.bgreen,Informational:A.bcyan}[sev]||A.white;
      pushLog('  ' + c(A.byellow,'Severity:') + ' ' + c(A.bold+sevColor, sev||''));
    } else if (/^- /.test(l)) {
      const [k,...v] = l.replace(/^- /,'').split(':');
      pushLog('  ' + c(A.byellow,k+':') + c(A.white,' '+v.join(':').trim()));
    }
  });
}

// ── Screen rendering ──────────────────────────────────────────────────────────
function renderHeader() {
  const w = W();
  const mem = getMemInfo();
  const cpu = getCpuLoad();
  const title = bold(c(A.bcyan, '0x') + c(A.bgreen, '-HUNT'));
  const ver   = c(A.gray, 'v2');
  const sess  = state.session
    ? c(A.bcyan, state.session.target) + c(A.gray, ' [') + c(A.byellow, state.session.phase||'recon') + c(A.gray, ']')
    : c(A.gray, 'no session');
  const agentSt = state.running ? c(A.bgreen+A.bold, '⚡ HUNTING') : c(A.gray, 'IDLE');
  const left  = ` ${title} ${ver}  ${sess}`;
  const right = `${agentSt}  RAM:${mem.pct}%  CPU:${cpu.load1}  `;
  const gap   = Math.max(1, w - visLen(left) - visLen(right));
  writeln(c(A.bgblack, left + ' '.repeat(gap) + right));
  write(c(A.cyan, '─'.repeat(w)));
}

function renderTabs() {
  const tabs = [
    { key:'log',      label:'[L] LOG',      color: A.cyan   },
    { key:'findings', label:'[F] FINDINGS', color: A.red    },
    { key:'shell',    label:'[S] SHELL',    color: A.yellow },
    { key:'files',    label:'[X] FILES',    color: A.blue   },
    { key:'sessions', label:'[E] SESSIONS', color: A.magenta},
  ];
  const parts = tabs.map(t => {
    const active = state.tab === t.key;
    const lbl = active
      ? c(A.bold + t.color + A.bgblack, ` ${t.label} `)
      : c(A.gray, ` ${t.label} `);
    return (active ? c(A.bold + t.color, '▶') : ' ') + lbl;
  });
  writeln('\n' + parts.join(c(A.gray, '│')));
  write(c(A.gray, '─'.repeat(W())));
}

function renderStatusBar() {
  const w = W();
  const mem = getMemInfo();
  const finds = state.session ? (state.session.findings||[]).length : 0;
  const cmds  = state.session ? (state.session.commandHistory||[]).length : 0;
  const iters = state.session ? (state.session.loopIteration||0) : 0;
  const left  = c(A.gray, ` finds:`) + c(A.byellow, finds) +
                c(A.gray, '  cmds:') + c(A.bcyan, cmds) +
                c(A.gray, '  iter:') + c(A.white, iters);
  const right = c(A.gray, `${fmtBytes(mem.used)}/${fmtBytes(mem.total)} `) +
                memBar(mem.pct, 10) + c(A.gray, ' ');
  const gap   = Math.max(1, w - visLen(left) - visLen(right));
  write(c(A.gray, '─'.repeat(w)) + '\n');
  write(left + ' '.repeat(gap) + right + '\n');
  const promptPfx = c(A.bgreen+A.bold, '0x') + c(A.gray, '> ');
  write(promptPfx + state.inputBuffer + A.show);
}

function renderLogTab() {
  const rows = H() - 7;
  const lines = state.logLines;
  const total = lines.length;
  const from  = Math.max(0, total - rows - state.logScroll);
  const slice = lines.slice(from, from + rows);
  if (slice.length < rows) {
    const pad = rows - slice.length;
    for (let i = 0; i < pad; i++) writeln('');
  }
  slice.forEach(l => writeln(l));
}

function renderFindingsTab() {
  const rows = H() - 7;
  const findings = state.session ? (state.session.findings||[]) : [];
  if (!findings.length) {
    for (let i = 0; i < rows - 2; i++) writeln('');
    writeln(c(A.gray, '  No findings yet.'));
    writeln('');
    return;
  }
  const lines = [];
  findings.forEach((f, i) => {
    const parts = (f.text||'').split('\n');
    let type='?', sev='?';
    parts.forEach(p => {
      if (p.includes('- Type:')) type = p.split('- Type:')[1]?.trim()||'?';
      if (p.includes('- Severity:')) sev = p.split('- Severity:')[1]?.trim()||'?';
    });
    const sevColor = {Critical:A.bred,High:A.red,Medium:A.byellow,Low:A.bgreen,Informational:A.bcyan}[sev]||A.white;
    lines.push(`  ${c(A.gray,'[')}${c(A.white,String(i+1).padStart(2))}${c(A.gray,']')} ${c(sevColor+A.bold, sev.padEnd(13))} ${c(A.byellow, type)}`);
    lines.push(`       ${c(A.gray, f.timestamp?.slice(0,19)||'')}`);
    lines.push('');
  });
  const total = lines.length;
  const from  = Math.max(0, total - rows);
  const slice = lines.slice(from, from+rows);
  if (slice.length < rows) for (let i = 0; i < rows-slice.length; i++) writeln('');
  slice.forEach(l => writeln(l));
}

function renderShellTab() {
  const rows = H() - 7;
  if (!state._shellLines) state._shellLines = [];
  const total = state._shellLines.length;
  const from  = Math.max(0, total - rows);
  const slice = state._shellLines.slice(from, from+rows);
  if (slice.length < rows) for (let i = 0; i < rows-slice.length; i++) writeln('');
  slice.forEach(l => writeln(l));
}

function renderFilesTab() {
  const rows = H() - 7;
  if (!state.session) {
    for (let i = 0; i < rows-1; i++) writeln('');
    writeln(c(A.gray, '  No active session.'));
    return;
  }
  const wsDir = join(WORKSPACE_DIR, state.session.id);
  if (!existsSync(wsDir)) {
    for (let i = 0; i < rows-1; i++) writeln('');
    writeln(c(A.gray, '  Workspace empty.'));
    return;
  }
  const lines = [];
  function walk(dir, prefix='', depth=0) {
    if (depth > 3) return;
    let entries;
    try { entries = readdirSync(dir, {withFileTypes:true}); } catch { return; }
    entries.forEach(e => {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        lines.push(prefix + c(A.blue, '▸ ') + c(A.bold+A.blue, e.name+'/'));
        walk(full, prefix+'  ', depth+1);
      } else {
        let sz = '';
        try { sz = fmtBytes(statSync(full).size); } catch {}
        lines.push(prefix + c(A.gray, '· ') + c(A.white, e.name) + c(A.gray, '  '+sz));
      }
    });
  }
  walk(wsDir);
  if (!lines.length) lines.push(c(A.gray, '  (empty)'));
  const from  = Math.max(0, lines.length - rows);
  const slice = lines.slice(from, from+rows);
  if (slice.length < rows) for (let i = 0; i < rows-slice.length; i++) writeln('');
  slice.forEach(l => writeln(l));
}

function renderSessionsTab() {
  const rows = H() - 7;
  const sessions = listSessions();
  if (!sessions.length) {
    for (let i = 0; i < rows-1; i++) writeln('');
    writeln(c(A.gray, '  No sessions. Use :new to start a hunt.'));
    return;
  }
  const lines = [];
  sessions.forEach((s, i) => {
    const active = state.session && state.session.id === s.id;
    const stColor = {active:A.bgreen,paused:A.byellow,error:A.bred,waiting_input:A.bmagenta}[s.status]||A.gray;
    const prefix = active ? c(A.bcyan+A.bold,'▶') : ' ';
    lines.push(`${prefix} ${c(A.gray,'[')}${c(A.white,String(i+1))}${c(A.gray,']')} ${c(A.bold+A.bcyan, s.target)}`);
    lines.push(`    ${c(stColor, s.status.padEnd(14))} ${c(A.byellow, s.phase.toUpperCase().padEnd(10))} ${c(A.gray, s.findingsCount+' finds  '+s.messagesCount+' msgs')}`);
    lines.push(`    ${c(A.gray, s.id.slice(0,8)+'…  '+new Date(s.updated).toLocaleString())}`);
    lines.push('');
  });
  const from  = Math.max(0, lines.length - rows);
  const slice = lines.slice(from, from+rows);
  if (slice.length < rows) for (let i = 0; i < rows-slice.length; i++) writeln('');
  slice.forEach(l => writeln(l));
}

function render() {
  write(A.clear + A.hide);
  renderHeader();
  renderTabs();
  switch (state.tab) {
    case 'log':      renderLogTab(); break;
    case 'findings': renderFindingsTab(); break;
    case 'shell':    renderShellTab(); break;
    case 'files':    renderFilesTab(); break;
    case 'sessions': renderSessionsTab(); break;
  }
  if (state.statusMsg) {
    write(c(state.statusColor, '  ' + state.statusMsg));
  }
  renderStatusBar();
}

function setStatus(msg, color = A.gray) {
  state.statusMsg = msg;
  state.statusColor = color;
}

// ── Input handling ────────────────────────────────────────────────────────────
function setupInput() {
  const rl = createInterface({ input: process.stdin, terminal: false });
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  rl.close();
  process.stdin.on('data', chunk => handleInput(chunk));
}

function handleInput(chunk) {
  if (chunk === '\x1b[A') { historyUp(); return; }
  if (chunk === '\x1b[B') { historyDown(); return; }
  if (chunk === '\x1b[C') { cursorRight(); return; }
  if (chunk === '\x1b[D') { cursorLeft(); return; }
  if (chunk === '\x03') { handleCtrlC(); return; }
  if (chunk === '\x0c') { state.logLines = []; render(); return; }
  if (chunk === '\x15') { state.inputBuffer = ''; state.inputCursor = 0; render(); return; }
  if (chunk === '\x09') { cycleTab(); return; }
  if (chunk === '\x7f' || chunk === '\x08') {
    if (state.inputCursor > 0) {
      state.inputBuffer = state.inputBuffer.slice(0, state.inputCursor-1) + state.inputBuffer.slice(state.inputCursor);
      state.inputCursor--;
    }
    render(); return;
  }
  if (chunk === '\r' || chunk === '\n') {
    const input = state.inputBuffer.trim();
    state.inputBuffer = '';
    state.inputCursor = 0;
    if (input) {
      state.shellHistory.unshift(input);
      if (state.shellHistory.length > 100) state.shellHistory.pop();
      state.shellHistIdx = -1;
      handleCommand(input);
    } else {
      render();
    }
    return;
  }
  if (chunk >= ' ') {
    state.inputBuffer = state.inputBuffer.slice(0, state.inputCursor) + chunk + state.inputBuffer.slice(state.inputCursor);
    state.inputCursor += chunk.length;
    render();
    return;
  }
}

function historyUp() {
  if (!state.shellHistory.length) return;
  state.shellHistIdx = Math.min(state.shellHistIdx + 1, state.shellHistory.length - 1);
  state.inputBuffer = state.shellHistory[state.shellHistIdx];
  state.inputCursor = state.inputBuffer.length;
  render();
}
function historyDown() {
  if (state.shellHistIdx <= 0) { state.shellHistIdx = -1; state.inputBuffer = ''; state.inputCursor = 0; render(); return; }
  state.shellHistIdx--;
  state.inputBuffer = state.shellHistory[state.shellHistIdx];
  state.inputCursor = state.inputBuffer.length;
  render();
}
function cursorLeft()  { if (state.inputCursor > 0) state.inputCursor--; render(); }
function cursorRight() { if (state.inputCursor < state.inputBuffer.length) state.inputCursor++; render(); }

function handleCtrlC() {
  if (state.running) {
    state.stopRequested = true;
    setStatus('Stop requested...', A.byellow);
    render();
  } else {
    write(A.show + A.reset + '\n');
    process.exit(0);
  }
}

function cycleTab() {
  const tabs = ['log','findings','shell','files','sessions'];
  const idx  = tabs.indexOf(state.tab);
  state.tab  = tabs[(idx + 1) % tabs.length];
  render();
}

// ── Command router ────────────────────────────────────────────────────────────
async function handleCommand(input) {
  const lower = input.toLowerCase();

  if (lower === ':log'      || lower === 'l') { state.tab = 'log';      render(); return; }
  if (lower === ':findings' || lower === 'f') { state.tab = 'findings'; render(); return; }
  if (lower === ':shell'    || lower === 's') { state.tab = 'shell';    render(); return; }
  if (lower === ':files'    || lower === 'x') { state.tab = 'files';    render(); return; }
  if (lower === ':sessions' || lower === 'e') { state.tab = 'sessions'; render(); return; }

  if (lower === 'j' || lower === ':down') { state.logScroll = Math.max(0, state.logScroll - 5); render(); return; }
  if (lower === 'k' || lower === ':up')   { state.logScroll += 5; render(); return; }
  if (lower === 'g' || lower === ':top')  { state.logScroll = state.logLines.length; render(); return; }
  if (lower === 'G' || lower === ':bot')  { state.logScroll = 0; render(); return; }

  if (lower === ':help' || lower === ':h' || lower === '?') { showHelp(); return; }
  if (lower === ':q' || lower === ':quit' || lower === ':exit') {
    write(A.show + A.reset + '\n');
    writeln(c(A.gray, 'Goodbye. Sessions saved.\n'));
    process.exit(0);
  }

  if (lower === ':ram'   || lower === 'checkram')  { showRAM(); return; }
  if (lower === ':cpu'   || lower === 'checkcpu')  { showCPU(); return; }
  if (lower === ':disk'  || lower === 'checkdisk') { showDisk(); return; }
  if (lower === ':net'   || lower === 'checknet')  { showNet(); return; }
  if (lower === ':tools' || lower === 'checktools'){ await showTools(); return; }
  if (lower === ':status'|| lower === 'status')    { showStatus(); return; }
  if (lower === ':groqtest')                       { await testGroq(); return; }

  if (lower === ':ls') { state.tab = 'sessions'; render(); return; }
  if (lower.startsWith(':load ') || lower.startsWith(':resume ')) {
    const arg = input.trim().split(/\s+/).slice(1).join(' ');
    await cmdLoad(arg); return;
  }
  if (lower.startsWith(':new')) { await cmdNew(); return; }
  if (lower.startsWith(':del ') || lower.startsWith(':delete ')) {
    const arg = input.trim().split(/\s+/).slice(1).join(' ');
    cmdDelete(arg); return;
  }
  if (lower === ':stop') { state.stopRequested = true; setStatus('Stop requested...', A.byellow); render(); return; }
  if (lower === ':go' || lower === ':continue' || lower === ':cont') { await cmdContinue(); return; }
  if (lower === ':report') { showReport(); return; }
  if (lower === ':clearlog') { state.logLines = []; setStatus('Log cleared', A.bgreen); render(); return; }

  if (lower.startsWith(':key ')) {
    const key = input.trim().split(/\s+/).slice(1).join(' ');
    await cmdSetKey(key); return;
  }
  if (lower === ':key') { await promptKey(); return; }

  if (state.tab === 'shell' || input.startsWith('!')) {
    const cmd = input.startsWith('!') ? input.slice(1).trim() : input;
    await runShellCmd(cmd); return;
  }

  if (state.session) { await cmdSend(input); return; }

  setStatus('Unknown command. Type :help or ? for commands.', A.bred);
  render();
}

// ── System info commands ──────────────────────────────────────────────────────
function showHelp() {
  state.tab = 'log';
  logSection('HELP', A.bcyan);
  const cmds = [
    ['TAB SWITCHING',''],
    ['  l / :log','Switch to LOG tab'],
    ['  f / :findings','Switch to FINDINGS tab'],
    ['  s / :shell','Switch to SHELL tab'],
    ['  x / :files','Switch to FILES tab'],
    ['  e / :sessions','Switch to SESSIONS tab'],
    ['  Tab key','Cycle through tabs'],
    ['',''],
    ['LOG NAVIGATION',''],
    ['  j / :down','Scroll log down'],
    ['  k / :up','Scroll log up'],
    ['  g / :top','Go to top'],
    ['  G / :bot','Go to bottom'],
    ['',''],
    ['SESSION MANAGEMENT',''],
    [':new','Start a new hunt (interactive)'],
    [':load <n|id>','Load session by number or ID prefix'],
    [':go / :cont','Continue/resume agent loop'],
    [':stop','Stop running agent'],
    [':del <n|id>','Delete a session'],
    [':report','Findings report for current session'],
    ['',''],
    ['AGENT',''],
    ['<text>','Send message to agent (session must be active)'],
    ['',''],
    ['SHELL',''],
    ['!<cmd>','Run shell command from any tab'],
    ['<cmd>','Run shell command (when in shell tab)'],
    ['',''],
    ['SYSTEM',''],
    [':key <gsk_...>','Set Groq API key'],
    [':status','Full system snapshot'],
    [':ram / :cpu','Memory / CPU info'],
    [':disk / :net','Disk / network info'],
    [':tools','Check pentest tools'],
    [':groqtest','Test Groq API connection'],
    [':clearlog','Clear log display'],
    [':q / :quit','Exit 0x-hunt'],
  ];
  cmds.forEach(([cmd, desc]) => {
    if (!cmd) { pushLog(''); return; }
    if (!desc) { pushLog(c(A.bold+A.bcyan, cmd)); return; }
    pushLog('  ' + c(A.byellow, cmd.padEnd(22)) + c(A.white, desc));
  });
  render();
}

function showRAM() {
  const m = getMemInfo();
  state.tab = 'log';
  logSection('MEMORY', A.bcyan);
  pushLog(`  ${c(A.gray,'Total    ')} ${c(A.white, fmtBytes(m.total))}`);
  pushLog(`  ${c(A.gray,'Used     ')} ${c(A.white, fmtBytes(m.used))}`);
  pushLog(`  ${c(A.gray,'Available')} ${c(A.white, fmtBytes(m.avail))}`);
  pushLog(`  ${c(A.gray,'Usage    ')} ${memBar(m.pct, 30)} ${c(A.bold, m.pct+'%')}`);
  render();
}

function showCPU() {
  const cpu = getCpuLoad();
  state.tab = 'log';
  logSection('CPU', A.bcyan);
  pushLog(`  ${c(A.gray,'Cores  ')} ${c(A.white, String(cpu.cores))}`);
  pushLog(`  ${c(A.gray,'Load 1m')} ${c(A.bold+A.bcyan, cpu.load1)}`);
  pushLog(`  ${c(A.gray,'Load 5m')} ${c(A.white, cpu.load5)}`);
  render();
}

function showDisk() {
  const d = getDiskInfo();
  state.tab = 'log';
  logSection('DISK', A.bcyan);
  pushLog(`  ${c(A.gray,'Total    ')} ${c(A.white, fmtBytes(d.total))}`);
  pushLog(`  ${c(A.gray,'Used     ')} ${c(A.white, fmtBytes(d.used))}`);
  pushLog(`  ${c(A.gray,'Available')} ${c(A.white, fmtBytes(d.avail))}`);
  pushLog(`  ${c(A.gray,'Usage    ')} ${memBar(d.pct, 30)} ${c(A.bold, d.pct+'%')}`);
  render();
}

function showNet() {
  const n = getNetInfo();
  state.tab = 'log';
  logSection('NETWORK', A.bcyan);
  pushLog(`  ${c(A.gray,'VPN      ')} ${n.vpn ? c(A.bgreen+A.bold,'✓ DETECTED') : c(A.gray,'not detected')}`);
  pushLog(`  ${c(A.gray,'Interfaces:')}`);
  n.ifaces.forEach(i => pushLog(`    ${c(A.bcyan, i.name.padEnd(14))} ${c(A.white, i.ip)}`));
  if (!n.ifaces.length) pushLog(c(A.gray, '    (none found)'));
  render();
}

async function showTools() {
  state.tab = 'log';
  setStatus('Checking tools...', A.byellow);
  render();
  const results = checkTools();
  logSection('TOOLS', A.bcyan);
  const present = results.filter(r => r.ok).map(r => r.tool);
  const missing = results.filter(r => !r.ok).map(r => r.tool);
  pushLog(`  ${c(A.bgreen,'✓')} ${c(A.white,'Found:   ')} ${c(A.bgreen, present.join(', ')||'none')}`);
  pushLog(`  ${c(A.bred,'✗')} ${c(A.white,'Missing: ')} ${c(A.gray, missing.join(', ')||'none')}`);
  pushLog(`  ${c(A.gray,'Coverage:')} ${c(A.bold, present.length+'/'+results.length)}`);
  setStatus('', '');
  render();
}

function showStatus() {
  const mem = getMemInfo(), cpu = getCpuLoad(), disk = getDiskInfo(), net = getNetInfo();
  state.tab = 'log';
  logSection('SYSTEM STATUS', A.bcyan);
  pushLog(`  ${c(A.gray,'Platform')}  ${c(A.white, process.platform+' ('+process.arch+')')}`);
  pushLog(`  ${c(A.gray,'Node.js ')}  ${c(A.white, process.version)}`);
  pushLog(`  ${c(A.gray,'Uptime  ')}  ${c(A.white, Math.floor(os.uptime()/3600)+'h '+Math.floor(os.uptime()%3600/60)+'m')}`);
  pushLog(`  ${c(A.gray,'RAM     ')}  ${c(A.white, fmtBytes(mem.used)+' / '+fmtBytes(mem.total))} ${memBar(mem.pct,15)} ${c(A.bold,mem.pct+'%')}`);
  pushLog(`  ${c(A.gray,'CPU     ')}  ${c(A.white, cpu.load1+' / '+cpu.load5+' ('+cpu.cores+' cores)')}`);
  pushLog(`  ${c(A.gray,'Disk    ')}  ${c(A.white, fmtBytes(disk.avail)+' free / '+fmtBytes(disk.total)+' total')}`);
  pushLog(`  ${c(A.gray,'VPN     ')}  ${net.vpn ? c(A.bgreen,'detected') : c(A.gray,'not detected')}`);
  pushLog(`  ${c(A.gray,'PID     ')}  ${c(A.white, String(process.pid))}`);
  pushLog(`  ${c(A.gray,'Sessions')}  ${c(A.white, String(listSessions().length))}`);
  render();
}

async function testGroq() {
  const key = loadKey();
  if (!key) { logSys('No API key set. Use :key <gsk_...>', A.bred); state.tab='log'; render(); return; }
  state.tab = 'log';
  logSys('Testing Groq API (3 attempts)...', A.byellow);
  render();
  for (let i = 1; i <= 3; i++) {
    try {
      const g = new Groq({ apiKey: key, timeout: 15000 });
      await g.chat.completions.create({ model:'llama-3.3-70b-versatile', messages:[{role:'user',content:'hi'}], max_tokens:3 });
      state.groq = g;
      logSys(`✓ Connected on attempt ${i}`, A.bgreen);
      render(); return;
    } catch(e) {
      logSys(`Attempt ${i} failed: ${e.message}`, A.bred);
      if (i < 3) { logSys('Waiting 2s...', A.gray); await sleep(2000); }
    }
  }
  const net = getNetInfo();
  logSys('✗ All attempts failed.', A.bred);
  logSys(`VPN status: ${net.vpn ? 'active' : 'not detected'}`, A.gray);
  logSys('Check VPN routing and verify key at console.groq.com', A.gray);
  render();
}

// ── Key management ────────────────────────────────────────────────────────────
const KEY_FILE = join(__dirname, '.groq_key');
function loadKey()  { try { return readFileSync(KEY_FILE,'utf8').trim(); } catch { return null; } }
function saveKey(k) { writeFileSync(KEY_FILE, k, {mode:0o600}); }

async function cmdSetKey(key) {
  if (!key || !key.startsWith('gsk_')) {
    logSys('Invalid key. Must start with gsk_', A.bred);
    state.tab = 'log'; render(); return;
  }
  saveKey(key);
  logSys('Key saved. Testing...', A.byellow);
  state.tab = 'log'; render();
  await testGroq();
}

async function promptKey() {
  write(A.show + '\n');
  write(c(A.bcyan, 'Groq API key (gsk_...): '));
  process.stdin.setRawMode(false);
  const key = await new Promise(resolve => {
    process.stdin.once('data', d => resolve(d.toString().trim()));
  });
  process.stdin.setRawMode(true);
  if (key) await cmdSetKey(key);
  render();
}

// ── Session commands ──────────────────────────────────────────────────────────
async function cmdNew() {
  write(A.show + '\n');
  process.stdin.setRawMode(false);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(res => rl.question(c(A.bcyan, q), res));
  write('\n' + c(A.bold+A.bcyan,'─── NEW HUNT ───────────────────────────────────────\n'));
  const target = (await ask('Target domain (e.g. target.com): ')).trim();
  if (!target) { rl.close(); process.stdin.setRawMode(true); render(); return; }
  write(c(A.gray, 'Scope (one per line, empty line to finish):\n'));
  const scopeLines = [];
  while (true) {
    const line = (await ask('  scope> ')).trim();
    if (!line) break;
    scopeLines.push(line);
  }
  if (!scopeLines.length) { logSys('No scope entered. Cancelled.', A.bred); rl.close(); process.stdin.setRawMode(true); render(); return; }
  const notes = (await ask('Notes (optional): ')).trim();
  rl.close();
  process.stdin.setRawMode(true);

  if (!state.groq) {
    const key = loadKey();
    if (!key) { logSys('No API key. Use :key <gsk_...> first.', A.bred); render(); return; }
    try {
      state.groq = new Groq({ apiKey:key, timeout:15000 });
    } catch(e) { logSys('Groq init failed: '+e.message, A.bred); render(); return; }
  }

  const s = createSession(target, scopeLines.join('\n'), notes);
  state.session = s;
  ensureWorkspace(s.id);
  state.tab = 'log';
  logSys(`Session created: ${s.id.slice(0,8)}`, A.bgreen);
  logSys(`Target: ${target}`, A.bcyan);
  const kickoff = `START HUNT\nTARGET: ${target}\nSCOPE:\n${scopeLines.join('\n')}${notes?'\nNOTES: '+notes:''}\n\nBegin passive recon. Identify the target's attack surface.`;
  render();
  await runAgentLoop(kickoff);
}

async function cmdLoad(arg) {
  const sessions = listSessions();
  let s = null;
  const n = parseInt(arg);
  if (!isNaN(n) && n >= 1 && n <= sessions.length) {
    s = loadSession(sessions[n-1].id);
  } else {
    const found = sessions.find(x => x.id.startsWith(arg) || x.target.toLowerCase().includes(arg.toLowerCase()));
    if (found) s = loadSession(found.id);
  }
  if (!s) { logSys(`Session not found: ${arg}`, A.bred); state.tab='sessions'; render(); return; }
  state.session = s;
  state.tab = 'log';
  state.logLines = [];
  (s.findings||[]).forEach(f => logFinding(f.text));
  logSys(`Loaded: ${s.target} [${s.phase}] — ${(s.findings||[]).length} findings, ${(s.commandHistory||[]).length} commands`, A.bgreen);
  if (!state.groq) {
    const key = loadKey();
    if (key) { try { state.groq = new Groq({ apiKey:key, timeout:15000 }); logSys('Groq key loaded.', A.gray); } catch {} }
  }
  render();
}

function cmdDelete(arg) {
  const sessions = listSessions();
  let target = null;
  const n = parseInt(arg);
  if (!isNaN(n) && n >= 1 && n <= sessions.length) target = sessions[n-1];
  else target = sessions.find(x => x.id.startsWith(arg));
  if (!target) { logSys('Session not found: '+arg, A.bred); render(); return; }
  try { unlinkSync(join(SESSIONS_DIR, `${target.id}.json`)); } catch {}
  if (state.session && state.session.id === target.id) state.session = null;
  logSys(`Deleted: ${target.target}`, A.byellow);
  state.tab = 'sessions'; render();
}

async function cmdContinue() {
  if (!state.session) { logSys('No active session. Use :new or :load.', A.bred); render(); return; }
  if (state.running)  { logSys('Agent already running.', A.byellow); render(); return; }
  if (!state.groq) {
    const key = loadKey();
    if (!key) { logSys('No API key. Use :key <gsk_...>', A.bred); render(); return; }
    try { state.groq = new Groq({ apiKey:key, timeout:15000 }); } catch(e) { logSys('Groq init failed: '+e.message, A.bred); render(); return; }
  }
  state.tab = 'log';
  const resumeMsg = `SESSION RESUMED. Phase: ${state.session.phase||'recon'}. Iteration: ${state.session.loopIteration||0}. Review last output and continue.`;
  render();
  await runAgentLoop(resumeMsg);
}

async function cmdSend(msg) {
  if (!state.session) { logSys('No active session.', A.bred); render(); return; }
  if (!state.groq) { logSys('Groq not connected. Use :key or :groqtest.', A.bred); render(); return; }
  if (state.running) { logSys('Agent running. Use :stop first.', A.byellow); render(); return; }
  state.tab = 'log';
  logSection('OPERATOR → AGENT', A.bgreen);
  pushLog(c(A.bgreen, '  ') + c(A.white, msg));
  render();
  await runAgentLoop(`OPERATOR INPUT: ${msg}`);
}

function showReport() {
  if (!state.session) { logSys('No active session.', A.bred); render(); return; }
  const s = state.session;
  state.tab = 'log';
  logSection(`REPORT — ${s.target}`, A.bcyan);
  pushLog(`  ${c(A.gray,'Status  ')} ${c(A.white, s.status)}`);
  pushLog(`  ${c(A.gray,'Phase   ')} ${c(A.byellow, (s.phase||'recon').toUpperCase())}`);
  pushLog(`  ${c(A.gray,'Commands')} ${c(A.white, String((s.commandHistory||[]).length))}`);
  pushLog(`  ${c(A.gray,'Findings')} ${c(s.findings?.length ? A.bred+A.bold : A.gray, String((s.findings||[]).length))}`);
  pushLog('');
  if (s.findings && s.findings.length) {
    s.findings.forEach((f, i) => {
      const parts = (f.text||'').split('\n');
      let type='?', sev='?', url='?';
      parts.forEach(p => {
        if (p.includes('- Type:')) type = p.split('- Type:')[1]?.trim()||'?';
        if (p.includes('- Severity:')) sev = p.split('- Severity:')[1]?.trim()||'?';
        if (p.includes('- URL')) url = p.split(/- URL[^:]*:/)[1]?.trim()||'?';
      });
      const sevColor = {Critical:A.bred,High:A.red,Medium:A.byellow,Low:A.bgreen,Informational:A.bcyan}[sev]||A.white;
      pushLog(`  [${i+1}] ${c(sevColor+A.bold,sev.padEnd(13))} ${c(A.byellow,type)}`);
      pushLog(`      ${c(A.gray,url)}`);
      pushLog('');
    });
  } else {
    pushLog(c(A.gray,'  No findings yet.'));
  }
  render();
}

// ── Shell passthrough ─────────────────────────────────────────────────────────
async function runShellCmd(cmd) {
  if (!state._shellLines) state._shellLines = [];
  state.tab = 'shell';
  state._shellLines.push(c(A.bgreen, '$ ') + c(A.white, cmd));
  setStatus('Running...', A.byellow);
  render();
  const wsDir = state.session ? ensureWorkspace(state.session.id) : os.homedir();
  const result = await new Promise(resolve => {
    const PATH = [process.env.PATH,'/root/go/bin',`${os.homedir()}/go/bin`,
      '/usr/local/bin','/usr/bin','/bin',`${os.homedir()}/.local/bin`].filter(Boolean).join(':');
    const proc = spawn('bash',['-c',cmd],{ cwd:wsDir, env:{...process.env,PATH,TERM:'xterm-256color'} });
    let stdout='', stderr='';
    proc.stdout.on('data', d => { stdout+=d; });
    proc.stderr.on('data', d => { stderr+=d; });
    proc.on('close', code => resolve({ stdout, stderr, exitCode:code??0 }));
    proc.on('error', e => resolve({ stdout:'', stderr:e.message, exitCode:1 }));
    setTimeout(() => { try{proc.kill();}catch{} resolve({ stdout, stderr:'[timeout]', exitCode:124 }); }, 30000);
  });
  if (result.stdout.trim()) result.stdout.trimEnd().split('\n').forEach(l => state._shellLines.push(l));
  if (result.stderr.trim()) result.stderr.trimEnd().split('\n').forEach(l => state._shellLines.push(c(A.red, l)));
  state._shellLines.push(c(result.exitCode===0 ? A.bgreen : A.bred, `[exit ${result.exitCode}]`));
  state._shellLines.push('');
  setStatus('', '');
  render();
}

// ── Agent loop ────────────────────────────────────────────────────────────────
async function runAgentLoop(initialMsg) {
  if (state.running) return;
  state.running = true;
  state.stopRequested = false;
  const s = state.session;
  s.status = 'active';
  saveSession(s);
  let firstMsg = initialMsg;
  for (let i = 0; i < 150; i++) {
    if (state.stopRequested) {
      s.status = 'paused'; saveSession(s);
      logSys('■ Agent stopped by operator', A.byellow);
      state.running = false; state.stopRequested = false;
      render(); return;
    }
    const result = await runAgentTurn(firstMsg);
    firstMsg = null;
    if (result.error) {
      s.status = 'error'; saveSession(s);
      logSys('⚠ Agent paused: API error', A.bred);
      state.running = false; render(); return;
    }
    if (result.needsInput) { state.running = false; render(); return; }
    await sleep(600);
    const fresh = loadSession(s.id);
    if (fresh) Object.assign(s, fresh);
    render();
  }
  s.status = 'paused'; saveSession(s);
  logSys('⚠ Iteration cap reached. Use :cont to resume.', A.byellow);
  state.running = false; render();
}

async function runAgentTurn(userMsg) {
  const s = state.session;
  if (userMsg) s.messages.push({ role:'user', content:userMsg });
  const recentMsgs = s.messages.slice(-60);
  setStatus(`Groq → iter ${s.loopIteration+1}...`, A.bcyan);
  render();
  let response;
  try {
    response = await state.groq.chat.completions.create({
      model      : 'llama-3.3-70b-versatile',
      messages   : [
        { role:'system', content:SYSTEM_PROMPT },
        { role:'user',   content:`TARGET: ${s.target}\nSCOPE:\n${s.scope}${s.notes?'\nNOTES: '+s.notes:''}\nPHASE: ${s.phase||'recon'}\nITERATION: ${s.loopIteration}` },
        ...recentMsgs,
      ],
      temperature: 0.15,
      max_tokens : 2048,
    });
  } catch(e) {
    logSys('Groq error: '+e.message, A.bred);
    return { error: true };
  }
  const text = response.choices[0].message.content;
  s.messages.push({ role:'assistant', content:text });
  s.loopIteration = (s.loopIteration||0) + 1;
  setStatus('', '');
  const phaseMatch = text.match(/\*\*PHASE:\*\*\s*(\w+)/i);
  if (phaseMatch) s.phase = phaseMatch[1].toLowerCase();
  const findMatches = [...text.matchAll(/🚨 FINDING:([\s\S]*?)(?=\n\n---|\n\n\*\*(?!🚨)|$)/g)];
  findMatches.forEach(m => {
    const f = { id:uuidv4(), text:'🚨 FINDING:'+m[1], timestamp:new Date().toISOString(), phase:s.phase };
    s.findings.push(f);
    logFinding(f.text);
  });
  logAI(text);
  if (text.includes('⏸ NEEDS INPUT:')) {
    s.status = 'waiting_input'; saveSession(s);
    logSys('⏸ Agent needs your input. Type your response and press Enter.', A.bmagenta);
    return { needsInput: true };
  }
  const cmdMatch = text.match(/```bash\n([\s\S]*?)```/);
  if (cmdMatch) {
    const cmd = cmdMatch[1].trim();
    if (!cmd) { saveSession(s); return { noCommand:true }; }
    logExec(cmd);
    s.commandHistory.push({ id:uuidv4(), cmd, ts:new Date().toISOString(), phase:s.phase });
    setStatus(`Running: ${cmd.slice(0,50)}…`, A.byellow);
    render();
    const result = await executeCommand(cmd, s.id, 120000);
    logResult(result);
    if (!state._shellLines) state._shellLines = [];
    state._shellLines.push(c(A.byellow,'[agent] $ ') + c(A.white, cmd));
    if (result.stdout.trim()) result.stdout.trimEnd().split('\n').slice(0,30).forEach(l => state._shellLines.push(c(A.gray,'  ')+l));
    if (result.stderr.trim()) result.stderr.trimEnd().split('\n').slice(0,5).forEach(l => state._shellLines.push(c(A.red,'  '+l)));
    state._shellLines.push('');
    const last = s.commandHistory[s.commandHistory.length-1];
    if (last) { last.stdout=result.stdout; last.stderr=result.stderr; last.exitCode=result.exitCode; }
    s.messages.push({ role:'user', content:[
      `COMMAND: \`${cmd}\``, `EXIT: ${result.exitCode}`,
      result.stdout ? `STDOUT:\n\`\`\`\n${result.stdout}\n\`\`\`` : 'STDOUT: (empty)',
      result.stderr ? `STDERR: ${result.stderr}` : '',
      result.truncated ? '⚠ Output truncated' : '',
    ].filter(Boolean).join('\n')});
    setStatus('', '');
    saveSession(s);
    render();
    return { command:cmd, result };
  }
  saveSession(s);
  return { noCommand:true };
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Boot ──────────────────────────────────────────────────────────────────────
async function boot() {
  const key = loadKey();
  write(A.clear + A.hide);
  writeln('');
  writeln(c(A.bcyan+A.bold, '  ██████╗ ██╗  ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗'));
  writeln(c(A.bcyan,        '  ██╔═████╗╚██╗██╔╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝'));
  writeln(c(A.bcyan,        '  ██║██╔██║ ╚███╔╝ █████╗███████║██║   ██║██╔██╗ ██║   ██║   '));
  writeln(c(A.cyan,         '  ████╔╝██║ ██╔██╗ ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   '));
  writeln(c(A.gray,         '  ╚██████╔╝██╔╝ ██╗      ██║  ██║╚██████╔╝██║ ╚████║   ██║   '));
  writeln(c(A.gray,         '   ╚═════╝ ╚═╝  ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝  '));
  writeln('');
  writeln(c(A.gray, '  Private Bug Bounty Hunter') + c(A.dim, '  //  Groq llama-3.3-70b'));
  writeln(c(A.gray, '  ') + c(A.bcyan, 'Type :help or ?   Tab = cycle tabs   Ctrl+C = stop/exit'));
  writeln('');
  const mem = getMemInfo(), cpu = getCpuLoad(), net = getNetInfo();
  writeln(c(A.gray, '  RAM  ') + memBar(mem.pct, 20) + c(A.white, ` ${mem.pct}%  ${fmtBytes(mem.used)}/${fmtBytes(mem.total)}`));
  writeln(c(A.gray, '  CPU  ') + c(A.white, `${cpu.cores} cores  load ${cpu.load1}`));
  writeln(c(A.gray, '  VPN  ') + (net.vpn ? c(A.bgreen,'detected') : c(A.gray,'not detected')));
  writeln(c(A.gray, '  Key  ') + (key ? c(A.bgreen,'✓ '+key.slice(0,12)+'...') : c(A.bred,'✗ not set  →  :key <gsk_...>')));
  writeln('');
  const sessions = listSessions();
  if (sessions.length) {
    writeln(c(A.gray, `  ${sessions.length} saved session(s):`));
    sessions.slice(0,3).forEach((s,i) => writeln(c(A.gray,`    [${i+1}] `) + c(A.bcyan, s.target) + c(A.gray, `  ${s.phase}  ${s.findingsCount} finds`)));
    writeln(c(A.gray, '  Use :load <n> to resume'));
    writeln('');
  }
  writeln(c(A.dim, '  Press any key to start...'));
  await new Promise(resolve => process.stdin.once('data', resolve));
  if (key) {
    try { state.groq = new Groq({ apiKey:key, timeout:15000 }); logSys('Groq key loaded.', A.gray); } catch {}
  }
  setupInput();
  render();
  setInterval(() => { if (!state.running) render(); }, 10000);
}

process.stdout.on('resize', () => render());
process.on('exit', () => write(A.show + A.reset + '\n'));
process.on('SIGTERM', () => { write(A.show + A.reset + '\n'); process.exit(0); });

boot().catch(e => { write(A.show+A.reset+'\n'); console.error(e); process.exit(1); });
