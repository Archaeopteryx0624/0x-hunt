import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import {
  readFileSync, writeFileSync, existsSync, mkdirSync,
  readdirSync, appendFileSync, unlinkSync, statSync
} from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import Groq from 'groq-sdk';
import { spawn, execSync } from 'child_process';
import os from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(join(__dirname, 'public')));

const SESSIONS_DIR  = join(__dirname, 'sessions');
const LOGS_DIR      = join(__dirname, 'logs');
const WORKSPACE_DIR = join(__dirname, 'workspace');
const SERVER_LOG    = join(__dirname, 'logs', 'server.log');

for (const d of [SESSIONS_DIR, LOGS_DIR, WORKSPACE_DIR]) {
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
}

// ── Structured logger ─────────────────────────────────────────────────────────

const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
const LOG_COLORS = { DEBUG: '\x1b[36m', INFO: '\x1b[32m', WARN: '\x1b[33m', ERROR: '\x1b[31m', RESET: '\x1b[0m' };

function log(level, module, message, data = null) {
  const ts  = new Date().toISOString();
  const line = `[${ts}] [${level}] [${module}] ${message}${data ? ' ' + JSON.stringify(data) : ''}`;
  const colored = `${LOG_COLORS[level] || ''}${line}${LOG_COLORS.RESET}`;

  console.log(colored);
  try { appendFileSync(SERVER_LOG, line + '\n'); } catch {}
}

const logger = {
  debug : (mod, msg, d) => log('DEBUG', mod, msg, d),
  info  : (mod, msg, d) => log('INFO',  mod, msg, d),
  warn  : (mod, msg, d) => log('WARN',  mod, msg, d),
  error : (mod, msg, d) => log('ERROR', mod, msg, d),
};

// ── System metrics ────────────────────────────────────────────────────────────

function getMemInfo() {
  try {
    // Works on Linux/Termux
    const raw = readFileSync('/proc/meminfo', 'utf8');
    const parse = key => {
      const m = raw.match(new RegExp(`${key}:\\s+(\\d+)`));
      return m ? parseInt(m[1]) * 1024 : 0; // kB → bytes
    };
    const total     = parse('MemTotal');
    const free      = parse('MemFree');
    const available = parse('MemAvailable');
    const buffers   = parse('Buffers');
    const cached    = parse('Cached');
    const used      = total - available;
    const pct       = total > 0 ? Math.round((used / total) * 100) : 0;
    return { total, free, available, used, buffers, cached, pct, source: 'procfs' };
  } catch {
    // Fallback: Node.js os module (less accurate — no cache/buffer distinction)
    const total     = os.totalmem();
    const free      = os.freemem();
    const used      = total - free;
    const pct       = Math.round((used / total) * 100);
    return { total, free, available: free, used, buffers: 0, cached: 0, pct, source: 'os' };
  }
}

function getCpuInfo() {
  try {
    const load = os.loadavg();
    const cpus = os.cpus();
    return {
      cores   : cpus.length,
      model   : cpus[0]?.model?.trim() || 'unknown',
      load1   : load[0].toFixed(2),
      load5   : load[1].toFixed(2),
      load15  : load[2].toFixed(2),
      loadPct : Math.min(100, Math.round((load[0] / cpus.length) * 100)),
    };
  } catch { return { cores: 1, model: 'unknown', load1: 0, load5: 0, load15: 0, loadPct: 0 }; }
}

function getDiskInfo() {
  try {
    const out = execSync('df -B1 . 2>/dev/null || df .', { encoding: 'utf8', timeout: 3000 });
    const lines = out.trim().split('\n');
    const parts = lines[1]?.split(/\s+/);
    if (parts && parts.length >= 4) {
      const total = parseInt(parts[1]) || 0;
      const used  = parseInt(parts[2]) || 0;
      const avail = parseInt(parts[3]) || 0;
      const pct   = total > 0 ? Math.round((used / total) * 100) : 0;
      return { total, used, avail, pct };
    }
  } catch {}
  return { total: 0, used: 0, avail: 0, pct: 0 };
}

function getNetworkInfo() {
  try {
    // Check default route / VPN
    const ifaces = os.networkInterfaces();
    const result = { interfaces: [], vpnDetected: false, publicIp: null };
    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const addr of addrs || []) {
        if (addr.family === 'IPv4' && !addr.internal) {
          result.interfaces.push({ name, address: addr.address, netmask: addr.netmask });
          // Common VPN interface names
          if (/^(tun|tap|wg|vpn|pptp|ppp)/i.test(name)) result.vpnDetected = true;
        }
      }
    }
    return result;
  } catch { return { interfaces: [], vpnDetected: false, publicIp: null }; }
}

function fmtBytes(b) {
  if (!b) return '0 B';
  if (b < 1024)       return `${b} B`;
  if (b < 1048576)    return `${(b/1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b/1048576).toFixed(1)} MB`;
  return `${(b/1073741824).toFixed(2)} GB`;
}

function getFullSystemSnapshot() {
  const mem  = getMemInfo();
  const cpu  = getCpuInfo();
  const disk = getDiskInfo();
  const net  = getNetworkInfo();
  return {
    ts      : new Date().toISOString(),
    uptime  : Math.floor(os.uptime()),
    platform: process.platform,
    arch    : process.arch,
    node    : process.version,
    mem, cpu, disk, net,
    process : {
      pid   : process.pid,
      rss   : process.memoryUsage().rss,
      heap  : process.memoryUsage().heapUsed,
      heapT : process.memoryUsage().heapTotal,
    },
  };
}

// ── Tool checker ──────────────────────────────────────────────────────────────

const TOOLS = [
  // recon
  'subfinder','assetfinder','amass','waybackurls','gau','katana','hakrawler',
  // dns/net
  'dig','nslookup','whois','nmap','ping','traceroute','host',
  // scanning
  'httpx','nuclei','nikto','whatweb',
  // fuzzing
  'ffuf','gobuster','dirb','arjun','wfuzz',
  // exploitation
  'dalfox','sqlmap','gf','qsreplace','xsstrike',
  // utils
  'curl','wget','python3','jq','git','go','bash',
];

async function checkTools() {
  const results = {};
  for (const tool of TOOLS) {
    try {
      execSync(`command -v ${tool}`, { stdio: 'ignore', timeout: 2000 });
      results[tool] = true;
    } catch { results[tool] = false; }
  }
  return results;
}

// ── Groq connectivity (VPN-aware) ─────────────────────────────────────────────

async function testGroqConnection(apiKey, retries = 3) {
  const net = getNetworkInfo();
  logger.info('GROQ', 'Testing connection', { vpnDetected: net.vpnDetected, interfaces: net.interfaces.map(i => i.name) });

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const g = new Groq({ apiKey, timeout: 15000 });
      await g.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: 'hi' }],
        max_tokens: 3,
      });
      logger.info('GROQ', `Connected on attempt ${attempt}`);
      return { ok: true, groq: g, attempt };
    } catch (e) {
      logger.warn('GROQ', `Attempt ${attempt} failed: ${e.message}`);
      if (attempt < retries) await new Promise(r => setTimeout(r, 2000 * attempt));
    }
  }
  return { ok: false, groq: null };
}

// ── Operator command parser ───────────────────────────────────────────────────

async function handleOperatorCommand(cmd, ws, activeSessionId) {
  const upper = cmd.trim().toUpperCase();

  // ── CHECKRAM ──
  if (upper === 'CHECKRAM') {
    const mem = getMemInfo();
    const bar = (pct) => {
      const filled = Math.round(pct / 5);
      return '[' + '█'.repeat(filled) + '░'.repeat(20 - filled) + `] ${pct}%`;
    };
    const lines = [
      '┌─ MEMORY ──────────────────────────────',
      `│  Total     : ${fmtBytes(mem.total)}`,
      `│  Used      : ${fmtBytes(mem.used)}`,
      `│  Available : ${fmtBytes(mem.available)}`,
      `│  Cached    : ${fmtBytes(mem.cached)}`,
      `│  Buffers   : ${fmtBytes(mem.buffers)}`,
      `│  Usage     : ${bar(mem.pct)}`,
      `│  Source    : ${mem.source}`,
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    logger.info('CMD', 'CHECKRAM executed', { pct: mem.pct });
    return;
  }

  // ── CHECKCPU ──
  if (upper === 'CHECKCPU') {
    const cpu = getCpuInfo();
    const lines = [
      '┌─ CPU ─────────────────────────────────',
      `│  Model     : ${cpu.model}`,
      `│  Cores     : ${cpu.cores}`,
      `│  Load 1m   : ${cpu.load1}  (${cpu.loadPct}% of capacity)`,
      `│  Load 5m   : ${cpu.load5}`,
      `│  Load 15m  : ${cpu.load15}`,
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    return;
  }

  // ── CHECKDISK ──
  if (upper === 'CHECKDISK') {
    const disk = getDiskInfo();
    const lines = [
      '┌─ DISK ────────────────────────────────',
      `│  Total     : ${fmtBytes(disk.total)}`,
      `│  Used      : ${fmtBytes(disk.used)}`,
      `│  Available : ${fmtBytes(disk.avail)}`,
      `│  Usage     : ${disk.pct}%`,
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    return;
  }

  // ── CHECKNET ──
  if (upper === 'CHECKNET') {
    const net = getNetworkInfo();
    const lines = [
      '┌─ NETWORK ─────────────────────────────',
      `│  VPN       : ${net.vpnDetected ? '✓ DETECTED' : '✗ not detected'}`,
      '│  Interfaces:',
      ...net.interfaces.map(i => `│    ${i.name.padEnd(10)} ${i.address}`),
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    return;
  }

  // ── CHECKTOOLS ──
  if (upper === 'CHECKTOOLS') {
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: 'Checking tools... (may take a few seconds)' });
    const tools = await checkTools();
    const present = Object.entries(tools).filter(([,v]) => v).map(([k]) => k);
    const missing = Object.entries(tools).filter(([,v]) => !v).map(([k]) => k);
    const lines = [
      '┌─ TOOLS ───────────────────────────────',
      `│  ✓ Found   : ${present.join(', ') || 'none'}`,
      `│  ✗ Missing : ${missing.join(', ') || 'none'}`,
      `│  Coverage  : ${present.length}/${TOOLS.length}`,
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    logger.info('CMD', 'CHECKTOOLS', { found: present.length, missing: missing.length });
    return;
  }

  // ── GROQTEST ──
  if (upper.startsWith('GROQTEST')) {
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: 'Testing Groq API connection...' });
    const net = getNetworkInfo();
    const key = localStorage_groqKey; // grabbed from stored key at init
    if (!key) {
      wsSend(ws, { type: 'operator_command_result', command: cmd, output: '✗ No API key set. Use the KEY button to set your Groq key.' });
      return;
    }
    const result = await testGroqConnection(key, 3);
    const lines = [
      '┌─ GROQ TEST ───────────────────────────',
      `│  Status    : ${result.ok ? '✓ CONNECTED' : '✗ FAILED'}`,
      `│  VPN       : ${net.vpnDetected ? '✓ active' : '✗ none detected'}`,
      `│  Attempt   : ${result.ok ? result.attempt : 'all 3 failed'}`,
      result.ok ? '' : '│  Tip: ensure VPN is routing API traffic',
      '└───────────────────────────────────────',
    ].filter(l => l !== null).join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    return;
  }

  // ── STATUS ──
  if (upper === 'STATUS') {
    const snap = getFullSystemSnapshot();
    const lines = [
      '┌─ SYSTEM STATUS ───────────────────────',
      `│  Platform  : ${snap.platform} (${snap.arch})`,
      `│  Node.js   : ${snap.node}`,
      `│  Uptime    : ${Math.floor(snap.uptime/3600)}h ${Math.floor((snap.uptime%3600)/60)}m`,
      `│  RAM       : ${fmtBytes(snap.mem.used)} / ${fmtBytes(snap.mem.total)} (${snap.mem.pct}%)`,
      `│  CPU Load  : ${snap.cpu.load1} / ${snap.cpu.load5} / ${snap.cpu.load15}`,
      `│  Disk Free : ${fmtBytes(snap.disk.avail)}`,
      `│  VPN       : ${snap.net.vpnDetected ? '✓ active' : '✗ none'}`,
      `│  PID       : ${snap.process.pid}`,
      `│  Heap      : ${fmtBytes(snap.process.heap)} / ${fmtBytes(snap.process.heapT)}`,
      `│  Sessions  : ${listSessions().length} total, ${activeLoops.size} active`,
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    return;
  }

  // ── CLEARLOG ──
  if (upper === 'CLEARLOG') {
    try { writeFileSync(SERVER_LOG, ''); } catch {}
    if (activeSessionId) {
      const p = join(LOGS_DIR, `${activeSessionId}.log`);
      try { writeFileSync(p, ''); } catch {}
    }
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: '✓ Logs cleared.' });
    return;
  }

  // ── HELP ──
  if (upper === 'HELP') {
    const lines = [
      '┌─ OPERATOR COMMANDS ───────────────────',
      '│  CHECKRAM    — RAM usage with bar graph',
      '│  CHECKCPU    — CPU load and core info',
      '│  CHECKDISK   — Disk space usage',
      '│  CHECKNET    — Network interfaces + VPN',
      '│  CHECKTOOLS  — Verify pentest tools',
      '│  GROQTEST    — Test Groq API reachability',
      '│  STATUS      — Full system snapshot',
      '│  CLEARLOG    — Clear server + session logs',
      '│  HELP        — This menu',
      '│',
      '│  Any other input → sent to agent as',
      '│  operator message or runs in terminal',
      '└───────────────────────────────────────',
    ].join('\n');
    wsSend(ws, { type: 'operator_command_result', command: cmd, output: lines });
    return;
  }

  return false; // not a system command
}

// Stored Groq key for GROQTEST (server-side reference)
let localStorage_groqKey = null;

// ── Session helpers ───────────────────────────────────────────────────────────

function loadSession(id) {
  const p = join(SESSIONS_DIR, `${id}.json`);
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; }
}

function saveSession(s) {
  s.updated = new Date().toISOString();
  writeFileSync(join(SESSIONS_DIR, `${s.id}.json`), JSON.stringify(s, null, 2));
}

function listSessions() {
  if (!existsSync(SESSIONS_DIR)) return [];
  return readdirSync(SESSIONS_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      try {
        const s = JSON.parse(readFileSync(join(SESSIONS_DIR, f), 'utf8'));
        return {
          id: s.id, target: s.target, scope: s.scope, status: s.status,
          created: s.created, updated: s.updated, phase: s.phase || 'recon',
          findingsCount: (s.findings||[]).length,
          messagesCount: (s.messages||[]).length,
        };
      } catch { return null; }
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b.updated) - new Date(a.updated));
}

function createSession(target, scope, notes) {
  const s = {
    id: uuidv4(), target, scope, notes: notes || '',
    status: 'active', phase: 'recon',
    created: new Date().toISOString(), updated: new Date().toISOString(),
    messages: [], findings: [], commandHistory: [], loopIteration: 0,
  };
  saveSession(s);
  return s;
}

// ── Command executor ──────────────────────────────────────────────────────────

const BLOCKED_PATTERNS = [
  /rm\s+-rf\s+\/(?!\w)/,
  /:\(\)\{.*\}/,
  /mkfs/,
  /dd\s+if=\/dev\/zero\s+of=\/dev\//,
  /shutdown\b/,
  /reboot\b/,
  /\bpoweroff\b/,
];

function isSafe(cmd) { return !BLOCKED_PATTERNS.some(p => p.test(cmd)); }

function ensureWorkspace(sid) {
  const d = join(WORKSPACE_DIR, sid);
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
  return d;
}

function executeCommand(cmd, sid, timeout = 90000) {
  if (!isSafe(cmd)) {
    logger.warn('EXEC', 'Blocked dangerous command', { cmd: cmd.slice(0, 80) });
    return Promise.resolve({ stdout: '', stderr: '⛔ BLOCKED: dangerous command pattern', exitCode: 1 });
  }

  const wsDir = ensureWorkspace(sid);
  const logPath = join(LOGS_DIR, `${sid}.log`);
  try { appendFileSync(logPath, `\n[${new Date().toISOString()}] $ ${cmd}\n`); } catch {}

  logger.debug('EXEC', `Running command`, { cmd: cmd.slice(0, 120), sid: sid.slice(0, 8) });

  return new Promise(resolve => {
    const PATH = [
      process.env.PATH,
      '/root/go/bin',
      '/usr/local/bin', '/usr/bin', '/bin',
      `${process.env.HOME || '/root'}/.local/bin`,
      `${process.env.HOME || '/root'}/go/bin`,
    ].filter(Boolean).join(':');

    const proc = spawn('bash', ['-c', cmd], {
      cwd: wsDir,
      env: { ...process.env, PATH, TERM: 'xterm-256color' },
    });

    let stdout = '', stderr = '', done = false;

    const finish = code => {
      if (done) return;
      done = true;
      const result = {
        stdout   : stdout.slice(0, 15000),
        stderr   : stderr.slice(0, 4000),
        exitCode : code ?? 0,
        truncated: stdout.length > 15000,
      };
      try { appendFileSync(logPath, `OUT:${result.stdout}\nERR:${result.stderr}\nEXIT:${code}\n`); } catch {}
      logger.debug('EXEC', `Command finished`, { exitCode: code, outLen: result.stdout.length });
      resolve(result);
    };

    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', finish);
    proc.on('error', e => { stderr += e.message; finish(1); });

    const timer = setTimeout(() => {
      try { proc.kill('SIGTERM'); } catch {}
      stderr += '\n⏱ [command timed out]';
      logger.warn('EXEC', 'Command timed out', { cmd: cmd.slice(0, 60) });
      finish(124);
    }, timeout);

    proc.on('close', () => clearTimeout(timer));
  });
}

// ── Agent system prompt ───────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are 0x-Hunt — an elite autonomous bug bounty hunter AI running on Linux (Termux aarch64). You operate inside a persistent agentic loop with full shell access.

## Mission
Systematically find security vulnerabilities in the given target, within scope. Be methodical: start passive, escalate gradually, document everything.

## Your Toolbox
Recon:        subfinder, assetfinder, amass, waybackurls, gau, katana, hakrawler
DNS/Net:      dig, nslookup, whois, host, traceroute, ping
Scanning:     nmap, httpx, nuclei, nikto, whatweb
Fuzzing:      ffuf, gobuster, dirb, arjun, wfuzz
Exploitation: dalfox (XSS), sqlmap (SQLi), gf, qsreplace, xsstrike
Utils:        bash, python3, grep, awk, sed, jq, tee, sort, uniq, cut

## Phases
1. RECON      — passive: whois, waybackurls, gau, subdomain enum
2. ENUMERATE  — httpx probe, tech detection, port scan (top 1000 first)
3. SCAN       — nuclei templates, nikto, directory bruteforce
4. FUZZ       — param discovery, input fuzzing, payload testing
5. EXPLOIT    — targeted exploitation of identified attack surfaces
6. REPORT     — structured vulnerability report

## Response Format — ALWAYS follow this EXACTLY:

**PHASE:** [current phase name]

**THINK:** [Concise analysis — what you know, what you found, what's next. MAX 3 sentences.]

**COMMAND:**
\`\`\`bash
<ONE shell command or pipeline — no interactive tools, no vi, no nano>
\`\`\`

**EXPECT:** [What output you anticipate]

---

## Special Blocks (use exactly when needed)

### On finding a vulnerability:
**🚨 FINDING:**
- Type: [XSS / SQLi / SSRF / IDOR / RCE / Auth Bypass / Open Redirect / CSRF / Info Disclosure / Other]
- Severity: [Critical / High / Medium / Low / Informational]
- URL/Asset: [exact affected URL or asset]
- Parameter: [vulnerable parameter, if applicable]
- Payload: [working payload or proof]
- Evidence: [response snippet, status code, or observable behavior]
- Impact: [what an attacker can do with this]
- Remediation: [recommended fix]

### When you need the operator:
**⏸ NEEDS INPUT:**
[Type: login / credentials / CAPTCHA / 2FA / confirmation]
[Exactly what you need and why — be specific]

### Phase transition:
**📋 PHASE COMPLETE: [PHASE NAME]**
[Summary: assets discovered, interesting findings, anomalies]
[Next phase plan]

## Rules
- ONE command per response — no exceptions
- Wait for output before proceeding
- NEVER probe out-of-scope assets — scope violation terminates the hunt
- Save useful output: use \`tee file.txt\` or \`> file.txt\`
- Chain discoveries: subdomains → httpx → nuclei → targeted fuzz
- No interactive commands: no vim, no interactive sqlmap, no less/more
- Rate-limit active scans to avoid detection and bans`;

const activeLoops = new Map();

function wsSend(ws, data) {
  try { if (ws && ws.readyState === 1) ws.send(JSON.stringify(data)); } catch {}
}

// ── Agent turn ────────────────────────────────────────────────────────────────

async function runAgentTurn(groq, session, userMsg, ws) {
  if (userMsg) session.messages.push({ role: 'user', content: userMsg });

  const recentMsgs = session.messages.slice(-60);

  let response;
  try {
    logger.debug('AGENT', 'Calling Groq', { iteration: session.loopIteration, msgs: recentMsgs.length });
    response = await groq.chat.completions.create({
      model      : 'llama-3.3-70b-versatile',
      messages   : [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user',   content: `TARGET: ${session.target}\nSCOPE:\n${session.scope}${session.notes ? '\nNOTES: ' + session.notes : ''}\nPHASE: ${session.phase || 'recon'}\nITERATION: ${session.loopIteration}` },
        ...recentMsgs,
      ],
      temperature: 0.15,
      max_tokens : 2048,
    });
  } catch (e) {
    const errMsg = `Groq API error: ${e.message}`;
    logger.error('AGENT', errMsg);
    wsSend(ws, { type: 'error', content: errMsg });
    return { error: errMsg };
  }

  const text = response.choices[0].message.content;
  session.messages.push({ role: 'assistant', content: text });
  session.loopIteration = (session.loopIteration || 0) + 1;

  wsSend(ws, { type: 'ai_message', content: text, sessionId: session.id, iteration: session.loopIteration });
  logger.info('AGENT', `Turn ${session.loopIteration} complete`, { phase: session.phase, chars: text.length });

  // Extract phase
  const phaseMatch = text.match(/\*\*PHASE:\*\*\s*(\w+)/i);
  if (phaseMatch) session.phase = phaseMatch[1].toLowerCase();

  // Extract findings
  const findingMatches = [...text.matchAll(/🚨 FINDING:([\s\S]*?)(?=\n\n---|\n\n\*\*(?!🚨)|$)/g)];
  findingMatches.forEach(m => {
    const f = { id: uuidv4(), text: '🚨 FINDING:' + m[1], timestamp: new Date().toISOString(), phase: session.phase };
    session.findings.push(f);
    wsSend(ws, { type: 'finding', finding: f, sessionId: session.id });
    logger.info('AGENT', '🚨 Finding captured', { phase: session.phase, iteration: session.loopIteration });
  });

  if (text.includes('📋 PHASE COMPLETE:')) {
    wsSend(ws, { type: 'phase_complete', content: text, sessionId: session.id });
    logger.info('AGENT', 'Phase complete', { phase: session.phase });
  }

  if (text.includes('⏸ NEEDS INPUT:')) {
    session.status = 'waiting_input';
    saveSession(session);
    wsSend(ws, { type: 'needs_input', content: text, sessionId: session.id });
    logger.info('AGENT', 'Waiting for operator input');
    return { needsInput: true };
  }

  const cmdMatch = text.match(/```bash\n([\s\S]*?)```/);
  if (cmdMatch) {
    const cmd = cmdMatch[1].trim();
    if (!cmd) { saveSession(session); return { noCommand: true }; }

    wsSend(ws, { type: 'executing', command: cmd, sessionId: session.id });
    const result = await executeCommand(cmd, session.id, 120000);

    session.commandHistory.push({
      id: uuidv4(), cmd,
      stdout: result.stdout, stderr: result.stderr,
      exitCode: result.exitCode,
      ts: new Date().toISOString(),
      phase: session.phase,
    });

    wsSend(ws, { type: 'command_result', command: cmd, output: result, sessionId: session.id });

    const outMsg = [
      `COMMAND: \`${cmd}\``,
      `EXIT: ${result.exitCode}`,
      result.stdout ? `STDOUT:\n\`\`\`\n${result.stdout}\n\`\`\`` : 'STDOUT: (no output)',
      result.stderr ? `STDERR: ${result.stderr}` : '',
      result.truncated ? '⚠ Output truncated to 15000 chars' : '',
    ].filter(Boolean).join('\n');

    session.messages.push({ role: 'user', content: outMsg });
    saveSession(session);
    return { command: cmd, result };
  }

  saveSession(session);
  return { noCommand: true };
}

// ── Agent loop ────────────────────────────────────────────────────────────────

async function runAgentLoop(groq, sessionId, initialMsg, ws) {
  const session = loadSession(sessionId);
  if (!session) return;

  session.status = 'active';
  saveSession(session);

  let firstMsg = initialMsg;
  const MAX = 150;

  for (let i = 0; i < MAX; i++) {
    const ls = activeLoops.get(sessionId);
    if (!ls || ls.stopRequested) {
      const s = loadSession(sessionId);
      if (s) { s.status = 'paused'; saveSession(s); }
      wsSend(ws, { type: 'agent_stopped', sessionId });
      activeLoops.delete(sessionId);
      logger.info('AGENT', 'Loop stopped by operator', { sessionId: sessionId.slice(0, 8) });
      return;
    }

    const result = await runAgentTurn(groq, session, firstMsg, ws);
    firstMsg = null;

    if (result.error) {
      const s = loadSession(sessionId);
      if (s) { s.status = 'error'; saveSession(s); }
      wsSend(ws, { type: 'agent_paused', reason: 'error', sessionId });
      activeLoops.delete(sessionId);
      return;
    }
    if (result.needsInput) { activeLoops.delete(sessionId); return; }

    await new Promise(r => setTimeout(r, 600));
    Object.assign(session, loadSession(sessionId));
  }

  const s = loadSession(sessionId);
  if (s) { s.status = 'paused'; saveSession(s); }
  wsSend(ws, { type: 'agent_paused', reason: 'iteration_cap', sessionId });
  activeLoops.delete(sessionId);
  logger.info('AGENT', 'Loop hit iteration cap', { sessionId: sessionId.slice(0, 8) });
}

// ── Real-time health broadcast ────────────────────────────────────────────────
// Pushes memory/cpu snapshot to all connected clients every 5 seconds

const connectedClients = new Set();

setInterval(() => {
  if (connectedClients.size === 0) return;
  const mem = getMemInfo();
  const cpu = getCpuInfo();
  const snap = {
    type    : 'health_tick',
    ts      : Date.now(),
    mem     : { total: mem.total, used: mem.used, available: mem.available, pct: mem.pct },
    cpu     : { load1: cpu.load1, loadPct: cpu.loadPct, cores: cpu.cores },
    loops   : activeLoops.size,
    sessions: listSessions().length,
  };
  for (const client of connectedClients) {
    wsSend(client, snap);
  }
}, 5000);

// ── WebSocket handler ─────────────────────────────────────────────────────────

wss.on('connection', ws => {
  let groq = null;
  let activeSessionId = null;

  connectedClients.add(ws);
  wsSend(ws, { type: 'connected', sessions: listSessions() });
  logger.info('WS', 'Client connected', { total: connectedClients.size });

  ws.on('message', async raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    // ── Init Groq ──
    if (msg.type === 'init_groq') {
      localStorage_groqKey = msg.apiKey;
      logger.info('GROQ', 'Attempting connection...');
      wsSend(ws, { type: 'groq_connecting' });

      const net = getNetworkInfo();
      if (!net.vpnDetected && net.interfaces.length === 0) {
        logger.warn('GROQ', 'No network interfaces found — possible connectivity issue');
      }

      const result = await testGroqConnection(msg.apiKey, 3);
      if (result.ok) {
        groq = result.groq;
        wsSend(ws, { type: 'groq_ready', attempt: result.attempt });
        logger.info('GROQ', 'Ready', { attempt: result.attempt });
      } else {
        const net2 = getNetworkInfo();
        wsSend(ws, {
          type   : 'groq_error',
          message: 'Connection failed after 3 attempts. Check your VPN and API key.',
          vpn    : net2.vpnDetected,
          ifaces : net2.interfaces.map(i => i.name),
        });
        logger.error('GROQ', 'Connection failed after retries');
      }
      return;
    }

    // ── Operator commands ──
    if (msg.type === 'operator_command') {
      const handled = await handleOperatorCommand(msg.command, ws, activeSessionId);
      if (handled !== false) return;
      // fallthrough to continue_agent if not a system command
    }

    // ── New session ──
    if (msg.type === 'new_session') {
      if (!groq) { wsSend(ws, { type: 'error', content: 'Set Groq API key first.' }); return; }
      const s = createSession(msg.target, msg.scope, msg.notes);
      activeSessionId = s.id;
      ensureWorkspace(s.id);
      wsSend(ws, { type: 'session_created', session: s });
      activeLoops.set(s.id, { running: true, ws, groq, stopRequested: false });
      const kickoff = `START HUNT\nTARGET: ${msg.target}\nSCOPE:\n${msg.scope}${msg.notes ? '\nNOTES: ' + msg.notes : ''}\n\nBegin passive recon. Identify the target's attack surface.`;
      logger.info('SESSION', 'New hunt launched', { target: msg.target, id: s.id.slice(0, 8) });
      runAgentLoop(groq, s.id, kickoff, ws);
      return;
    }

    // ── Resume session ──
    if (msg.type === 'resume_session') {
      if (!groq) { wsSend(ws, { type: 'error', content: 'Set Groq API key first.' }); return; }
      const s = loadSession(msg.sessionId);
      if (!s) { wsSend(ws, { type: 'error', content: 'Session not found.' }); return; }
      activeSessionId = s.id;
      wsSend(ws, { type: 'session_resumed', session: s, history: s.messages, findings: s.findings, commandHistory: s.commandHistory });
      if (msg.autoResume && s.status !== 'waiting_input') {
        activeLoops.set(s.id, { running: true, ws, groq, stopRequested: false });
        const resumeMsg = `SESSION RESUMED after crash/restart. Phase: ${s.phase || 'recon'}. Iteration: ${s.loopIteration || 0}. Review last output and continue.`;
        runAgentLoop(groq, s.id, resumeMsg, ws);
        logger.info('SESSION', 'Auto-resumed', { id: s.id.slice(0, 8), phase: s.phase });
      }
      return;
    }

    // ── Continue / operator input ──
    if (msg.type === 'continue_agent' || msg.type === 'operator_input') {
      if (!groq) return;
      const sid = msg.sessionId;
      if (!sid) return;
      if (activeLoops.has(sid)) return;
      const s = loadSession(sid);
      if (!s) return;
      const content = msg.type === 'operator_input'
        ? `OPERATOR INPUT: ${msg.content}`
        : (msg.message || 'Continue the hunt.');
      activeLoops.set(sid, { running: true, ws, groq, stopRequested: false });
      runAgentLoop(groq, sid, content, ws);
      return;
    }

    // ── Stop agent ──
    if (msg.type === 'stop_agent') {
      const sid = msg.sessionId;
      const ls = activeLoops.get(sid);
      if (ls) {
        ls.stopRequested = true;
      } else {
        const s = loadSession(sid);
        if (s) { s.status = 'paused'; saveSession(s); }
        wsSend(ws, { type: 'agent_stopped', sessionId: sid });
      }
      return;
    }

    if (msg.type === 'list_sessions') {
      wsSend(ws, { type: 'sessions_list', sessions: listSessions() });
      return;
    }

    if (msg.type === 'delete_session') {
      const ls = activeLoops.get(msg.sessionId);
      if (ls) ls.stopRequested = true;
      const p = join(SESSIONS_DIR, `${msg.sessionId}.json`);
      try { if (existsSync(p)) unlinkSync(p); } catch {}
      wsSend(ws, { type: 'sessions_list', sessions: listSessions() });
      return;
    }

    if (msg.type === 'read_file') {
      const sid = msg.sessionId;
      if (!sid) return;
      try {
        const safe = msg.path.replace(/\.\./g, '').replace(/^\//, '');
        const full = join(WORKSPACE_DIR, sid, safe);
        const sz   = statSync(full).size;
        if (sz > 500000) { wsSend(ws, { type: 'file_content', path: msg.path, content: `[Too large: ${sz} bytes]` }); return; }
        wsSend(ws, { type: 'file_content', path: msg.path, content: readFileSync(full, 'utf8') });
      } catch (e) { wsSend(ws, { type: 'error', content: 'Cannot read: ' + e.message }); }
      return;
    }

    if (msg.type === 'run_manual_command') {
      const sid = msg.sessionId;
      if (!sid) return;
      const r = await executeCommand(msg.command, sid, 30000);
      wsSend(ws, { type: 'manual_command_result', command: msg.command, output: r, sessionId: sid });
      return;
    }

    if (msg.type === 'list_workspace') {
      const sid = msg.sessionId;
      if (!sid) return;
      try {
        const dir = join(WORKSPACE_DIR, sid);
        if (!existsSync(dir)) { wsSend(ws, { type: 'workspace_files', files: [], sessionId: sid }); return; }
        function walk(d, depth = 0) {
          if (depth > 4) return [];
          return readdirSync(d, { withFileTypes: true }).map(e => {
            const full = join(d, e.name);
            const rel  = full.replace(join(WORKSPACE_DIR, sid) + '/', '');
            if (e.isDirectory()) return { name: e.name, type: 'dir', path: rel, children: walk(full, depth + 1) };
            const size = (() => { try { return statSync(full).size; } catch { return 0; } })();
            return { name: e.name, type: 'file', path: rel, size };
          });
        }
        wsSend(ws, { type: 'workspace_files', files: walk(dir), sessionId: sid });
      } catch { wsSend(ws, { type: 'workspace_files', files: [], sessionId: sid }); }
      return;
    }

    // ── Get system metrics on demand ──
    if (msg.type === 'get_metrics') {
      wsSend(ws, { type: 'metrics', data: getFullSystemSnapshot() });
      return;
    }
  });

  ws.on('close', () => {
    connectedClients.delete(ws);
    logger.info('WS', 'Client disconnected', { remaining: connectedClients.size });
  });
});

// ── REST API ──────────────────────────────────────────────────────────────────

app.get('/api/sessions', (_, res) => res.json(listSessions()));

app.get('/api/sessions/:id', (req, res) => {
  const s = loadSession(req.params.id);
  s ? res.json(s) : res.status(404).json({ error: 'Not found' });
});

app.delete('/api/sessions/:id', (req, res) => {
  const ls = activeLoops.get(req.params.id);
  if (ls) ls.stopRequested = true;
  const p = join(SESSIONS_DIR, `${req.params.id}.json`);
  if (existsSync(p)) { unlinkSync(p); res.json({ deleted: true }); }
  else res.status(404).json({ error: 'Not found' });
});

app.get('/api/sessions/:id/log', (req, res) => {
  const p = join(LOGS_DIR, `${req.params.id}.log`);
  existsSync(p) ? res.type('text').send(readFileSync(p, 'utf8')) : res.status(404).json({ error: 'No log' });
});

app.get('/api/health', (_, res) => {
  const snap = getFullSystemSnapshot();
  res.json({
    status      : 'ok',
    activeSessions: activeLoops.size,
    sessions    : listSessions().length,
    clients     : connectedClients.size,
    mem         : { used: snap.mem.used, total: snap.mem.total, pct: snap.mem.pct },
    cpu         : { load1: snap.cpu.load1, loadPct: snap.cpu.loadPct },
    uptime      : snap.uptime,
  });
});

app.get('/api/metrics', (_, res) => res.json(getFullSystemSnapshot()));

app.get('/api/log', (_, res) => {
  existsSync(SERVER_LOG)
    ? res.type('text').send(readFileSync(SERVER_LOG, 'utf8'))
    : res.json({ log: '' });
});

// ── Boot ──────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  const snap = getFullSystemSnapshot();
  console.log('\n  ██████╗ ██╗  ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗');
  console.log('  ██╔═████╗╚██╗██╔╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝');
  console.log('  ██║██╔██║ ╚███╔╝ █████╗███████║██║   ██║██╔██╗ ██║   ██║   ');
  console.log('  ████╔╝██║ ██╔██╗ ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ');
  console.log('  ╚██████╔╝██╔╝ ██╗      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ');
  console.log('   ╚═════╝ ╚═╝  ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ');
  console.log('\n  Private Bug Bounty Hunter // Powered by Groq');
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  → RAM  : ${fmtBytes(snap.mem.used)} / ${fmtBytes(snap.mem.total)} (${snap.mem.pct}%)`);
  console.log(`  → CPU  : ${snap.cpu.cores} cores, load ${snap.cpu.load1}`);
  console.log(`  → VPN  : ${snap.net.vpnDetected ? 'detected' : 'not detected'}`);
  console.log(`  → Node : ${snap.node}\n`);
  logger.info('SERVER', `Started on port ${PORT}`, { pid: process.pid, arch: snap.arch });
});
