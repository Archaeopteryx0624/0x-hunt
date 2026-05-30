#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
//  0x-HUNT  v2  — Autonomous Bug Bounty Hunter  (pure terminal / Termux)
// ─────────────────────────────────────────────────────────────────────────────
import {
  readFileSync, writeFileSync, existsSync, mkdirSync,
  readdirSync, appendFileSync, unlinkSync, statSync,
} from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createInterface } from 'readline';
import { spawn, execSync } from 'child_process';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';
import Groq from 'groq-sdk';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Dirs ──────────────────────────────────────────────────────────────────────
const SESSIONS_DIR  = join(__dirname, 'sessions');
const LOGS_DIR      = join(__dirname, 'logs');
const WORKSPACE_DIR = join(__dirname, 'workspace');
for (const d of [SESSIONS_DIR, LOGS_DIR, WORKSPACE_DIR])
  if (!existsSync(d)) mkdirSync(d, { recursive: true });

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const A = {
  reset  : '\x1b[0m',
  bold   : '\x1b[1m',
  dim    : '\x1b[2m',
  black  : '\x1b[30m',
  red    : '\x1b[31m',
  green  : '\x1b[32m',
  yellow : '\x1b[33m',
  blue   : '\x1b[34m',
  magenta: '\x1b[35m',
  cyan   : '\x1b[36m',
  white  : '\x1b[37m',
  gray   : '\x1b[90m',
  bred   : '\x1b[91m',
  bgreen : '\x1b[92m',
  byellow: '\x1b[93m',
  bblue  : '\x1b[94m',
  bmagenta:'\x1b[95m',
  bcyan  : '\x1b[96m',
  bwhite : '\x1b[97m',
  bgblack: '\x1b[40m',
  bgred  : '\x1b[41m',
  bggreen: '\x1b[42m',
  bgyellow:'\x1b[43m',
  bgblue : '\x1b[44m',
  bgmagenta:'\x1b[45m',
  bgcyan : '\x1b[46m',
  bgwhite: '\x1b[47m',
  clear  : '\x1b[2J\x1b[H',
  clearln: '\x1b[2K\r',
  up     : (n=1) => `\x1b[${n}A`,
  col    : (n=1) => `\x1b[${n}G`,
  hide   : '\x1b[?25l',
  show   : '\x1b[?25h',
  save   : '\x1b[s',
  restore: '\x1b[u',
};

const W = () => process.stdout.columns  || 80;
const H = () => process.stdout.rows     || 24;

function c(color, text) { return `${color}${text}${A.reset}`; }
function bold(text)      { return `${A.bold}${text}${A.reset}`; }
function dim(text)       { return `${A.dim}${text}${A.reset}`; }

function write(...args)  { process.stdout.write(args.join('')); }
function writeln(...args){ process.stdout.write(args.join('') + '\n'); }

// ── Terminal width helpers ────────────────────────────────────────────────────
function stripAnsi(s) { return s.replace(/\x1b\[[0-9;]*m/g, ''); }
function visLen(s)    { return stripAnsi(s).length; }

function hr(char = '─', color = A.gray) {
  return c(color, char.repeat(W()));
}

function padEnd(s, len) {
  const vis = visLen(s);
  return vis < len ? s + ' '.repeat(len - vis) : s;
}

function truncate(s, len) {
  const plain = stripAnsi(s);
  if (plain.length <= len) return s;
  return plain.slice(0, len - 1) + '…';
}

function box(title, lines, borderColor = A.cyan) {
  const w = Math.min(W() - 2, 78);
  const top    = c(borderColor, '┌─ ') + c(A.bold + A.bcyan, title) + c(borderColor, ' ' + '─'.repeat(Math.max(0, w - title.length - 4)) + '┐');
  const bottom = c(borderColor, '└' + '─'.repeat(w) + '┘');
  const rows = lines.map(l => {
    const plain = stripAnsi(l);
    const pad = w - 2 - plain.length;
    return c(borderColor, '│ ') + l + ' '.repeat(Math.max(0, pad)) + c(borderColor, ' │');
  });
  return [top, ...rows, bottom].join('\n');
}

// ── System metrics ────────────────────────────────────────────────────────────
function getMemInfo() {
  try {
    const raw     = readFileSync('/proc/meminfo', 'utf8');
    const parse   = key => { const m = raw.match(new RegExp(`${key}:\\s+(\\d+)`)); return m ? parseInt(m[1]) * 1024 : 0; };
    const total   = parse('MemTotal');
    const avail   = parse('MemAvailable');
    const used    = total - avail;
    return { total, used, avail, pct: total ? Math.round(used/total*100) : 0 };
  } catch {
    const t = os.totalmem(), f = os.freemem();
    return { total: t, used: t-f, avail: f, pct: Math.round((t-f)/t*100) };
  }
}

function getCpuLoad() {
  try { const l = os.loadavg(); return { load1: l[0].toFixed(2), load5: l[1].toFixed(2), cores: os.cpus().length }; }
  catch { return { load1: '?', load5: '?', cores: 1 }; }
}

function fmtBytes(b) {
  if (!b) return '0B';
  if (b < 1024)       return b + 'B';
  if (b < 1048576)    return (b/1024).toFixed(0) + 'K';
  if (b < 1073741824) return (b/1048576).toFixed(1) + 'M';
  return (b/1073741824).toFixed(2) + 'G';
}

function memBar(pct, width = 20) {
  const filled = Math.round(pct / 100 * width);
  const color  = pct > 90 ? A.bred : pct > 70 ? A.byellow : A.bgreen;
  return c(color, '█'.repeat(filled)) + c(A.gray, '░'.repeat(width - filled));
}

function getDiskInfo() {
  try {
    const out   = execSync('df -B1 . 2>/dev/null || df .', { encoding: 'utf8', timeout: 3000 });
    const parts = out.trim().split('\n')[1]?.split(/\s+/);
    if (parts && parts.length >= 4) {
      const total = parseInt(parts[1])||0, used = parseInt(parts[2])||0, avail = parseInt(parts[3])||0;
      return { total, used, avail, pct: total ? Math.round(used/total*100) : 0 };
    }
  } catch {}
  return { total:0, used:0, avail:0, pct:0 };
}

function getNetInfo() {
  const ifaces = os.networkInterfaces();
  const result = { ifaces: [], vpn: false };
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const addr of addrs||[]) {
      if (addr.family === 'IPv4' && !addr.internal) {
        result.ifaces.push({ name, ip: addr.address });
        if (/^(tun|tap|wg|vpn|ppp)/i.test(name)) result.vpn = true;
      }
    }
  }
  return result;
}

const TOOLS = ['subfinder','assetfinder','waybackurls','gau','katana','hakrawler',
               'dig','whois','nmap','httpx','nuclei','nikto','whatweb',
               'ffuf','gobuster','arjun','dalfox','sqlmap','gf','qsreplace',
               'curl','wget','python3','jq','git','go'];

function checkTools() {
  return TOOLS.map(t => {
    try { execSync(`command -v ${t}`, { stdio:'ignore', timeout:1500 }); return { tool:t, ok:true }; }
    catch { return { tool:t, ok:false }; }
  });
}

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
  return readdirSync(SESSIONS_DIR).filter(f => f.endsWith('.json')).map(f => {
    try {
      const s = JSON.parse(readFileSync(join(SESSIONS_DIR, f), 'utf8'));
      return { id:s.id, target:s.target, status:s.status, phase:s.phase||'recon',
               findingsCount:(s.findings||[]).length, messagesCount:(s.messages||[]).length,
               updated:s.updated, created:s.created };
    } catch { return null; }
  }).filter(Boolean).sort((a,b) => new Date(b.updated)-new Date(a.updated));
}

function createSession(target, scope, notes) {
  const s = {
    id:uuidv4(), target, scope, notes:notes||'',
    status:'active', phase:'recon',
    created:new Date().toISOString(), updated:new Date().toISOString(),
    messages:[], findings:[], commandHistory:[], loopIteration:0,
  };
  saveSession(s); return s;
}

function ensureWorkspace(sid) {
  const d = join(WORKSPACE_DIR, sid);
  if (!existsSync(d)) mkdirSync(d, {recursive:true});
  return d;
}

// ── Command execution ─────────────────────────────────────────────────────────
const BLOCKED = [/rm\s+-rf\s+\/(?!\w)/, /:\(\)\{.*\}/, /mkfs/, /shutdown\b/, /reboot\b/, /\bpoweroff\b/];
function isSafe(cmd) { return !BLOCKED.some(p => p.test(cmd)); }

function executeCommand(cmd, sid, timeout=120000) {
  if (!isSafe(cmd)) return Promise.resolve({ stdout:'', stderr:'⛔ BLOCKED', exitCode:1 });
  const wsDir = ensureWorkspace(sid);
  const logPath = join(LOGS_DIR, `${sid}.log`);
  try { appendFileSync(logPath, `\n[${new Date().toISOString()}] $ ${cmd}\n`); } catch {}
  return new Promise(resolve => {
    const PATH = [process.env.PATH, '/root/go/bin', `${os.homedir()}/go/bin`,
      '/usr/local/bin','/usr/bin','/bin',`${os.homedir()}/.local/bin`].filter(Boolean).join(':');
    const proc = spawn('bash',['-c',cmd],{ cwd:wsDir, env:{...process.env,PATH,TERM:'xterm-256color'} });
    let stdout='', stderr='', done=false;
    const finish = code => {
      if (done) return; done=true;
      const r = { stdout:stdout.slice(0,20000), stderr:stderr.slice(0,4000), exitCode:code??0, truncated:stdout.length>20000 };
      try { appendFileSync(logPath, `OUT:${r.stdout}\nERR:${r.stderr}\nEXIT:${code}\n`); } catch {}
      resolve(r);
    };
    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', finish);
    proc.on('error', e => { stderr += e.message; finish(1); });
    const timer = setTimeout(() => { try{proc.kill('SIGTERM');}catch{} stderr+='\n⏱ [timeout]'; finish(124); }, timeout);
    proc.on('close', () => clearTimeout(timer));
  });
}

// ── Agent system prompt ───────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are 0x-Hunt — an elite autonomous bug bounty hunter AI running on Linux/Termux. You operate inside a persistent agentic loop with full shell access.

## Mission
Systematically find security vulnerabilities in the given target, within scope. Be methodical: start passive, escalate gradually, document everything.

## Toolbox
Recon:        subfinder, assetfinder, waybackurls, gau, katana, hakrawler
DNS/Net:      dig, nslookup, whois, host, nmap, ping
Scanning:     httpx, nuclei, nikto, whatweb
Fuzzing:      ffuf, gobuster, arjun, wfuzz
Exploitation: dalfox (XSS), sqlmap (SQLi), gf, qsreplace
Utils:        bash, python3, grep, awk, sed, jq, tee, sort, uniq, cut

## Phases: RECON → ENUMERATE → SCAN → FUZZ → EXPLOIT → REPORT

## Response Format — ALWAYS follow EXACTLY:

**PHASE:** [current phase]

**THINK:** [Analysis — what you know, what's next. MAX 3 sentences.]

**COMMAND:**
\`\`\`bash
<ONE non-interactive shell command or pipeline>
\`\`\`

**EXPECT:** [Expected output]

---

### On finding a vulnerability:
**🚨 FINDING:**
- Type: [XSS/SQLi/SSRF/IDOR/RCE/Auth Bypass/Open Redirect/CSRF/Info Disclosure]
- Severity: [Critical/High/Medium/Low/Informational]
- URL/Asset: [exact URL]
- Parameter: [vulnerable param]
- Payload: [working payload]
- Evidence: [response/behavior]
- Impact: [what attacker can do]
- Remediation: [fix]

### When you need the operator:
**⏸ NEEDS INPUT:**
[Type: login/credentials/CAPTCHA/2FA]
[Exactly what you need and why]

### Phase transition:
**📋 PHASE COMPLETE: [PHASE]**
[Summary and next phase plan]

## Rules
- ONE command per response — no exceptions
- NEVER probe out-of-scope assets
- No interactive commands (no vim, interactive sqlmap, etc.)
- Save output: use tee file.txt`;

// ── TUI State ─────────────────────────────────────────────────────────────────
const state = {
  groq          : null,
  session       : null,
  running       : false,
  stopRequested : false,
  tab           : 'log',
  logLines      : [],
  logScroll     : 0,
  shellHistory  : [],
  shellHistIdx  : -1,
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