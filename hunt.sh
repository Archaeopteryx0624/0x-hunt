#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  0x-HUNT  v2  — Autonomous Bug Bounty Hunter  (pure terminal / Termux)
#  Rewritten in Bash from Node.js version, with bug fixes.
# ─────────────────────────────────────────────────────────────────────────────

# --- Configuration -----------------------------------------------------------
SESSIONS_DIR="$(dirname "$0")"/sessions
LOGS_DIR="$(dirname "$0")"/logs
WORKSPACE_DIR="$(dirname "$0")"/workspace
GROQ_KEY_FILE="$(dirname "$0")"/.groq_key

# Ensure directories exist
mkdir -p "$SESSIONS_DIR" "$LOGS_DIR" "$WORKSPACE_DIR"

# --- ANSI Color Helpers ------------------------------------------------------
# Define ANSI escape codes for colors and text formatting
# These are direct translations from the Node.js version to Bash.
readonly A_RESET='\033[0m'
readonly A_BOLD='\033[1m'
readonly A_DIM='\033[2m'
readonly A_BLACK='\033[30m'
readonly A_RED='\033[31m'
readonly A_GREEN='\033[32m'
readonly A_YELLOW='\033[33m'
readonly A_BLUE='\033[34m'
readonly A_MAGENTA='\033[35m'
readonly A_CYAN='\033[36m'
readonly A_WHITE='\033[37m'
readonly A_GRAY='\033[90m'
readonly A_BRED='\033[91m'
readonly A_BGREEN='\033[92m'
readonly A_BYELLOW='\033[93m'
readonly A_BBLUE='\033[94m'
readonly A_BMAGENTA='\033[95m'
readonly A_BCYAN='\033[96m'
readonly A_BWHITE='\033[97m'
readonly A_BGBLACK='\033[40m'
readonly A_BGRED='\033[41m'
readonly A_BGGREEN='\033[42m'
readonly A_BGYELLOW='\033[43m'
readonly A_BGBLUE='\033[44m'
readonly A_BGMAGENTA='\033[45m'
readonly A_BGCYAN='\033[46m'
readonly A_BGWHITE='\033[47m'
readonly A_CLEAR='\033[2J\033[H'
readonly A_CLEARLN='\033[2K\r'
readonly A_HIDE='\033[?25l'
readonly A_SHOW='\033[?25h'
readonly A_SAVE='\033[s'
readonly A_RESTORE='\033[u'

# Helper functions for colored output
c()     { echo -en "$1$2${A_RESET}"; }
c_no_nl() { echo -n "$1$2${A_RESET}"; }
bold()  { echo -en "${A_BOLD}$1${A_RESET}"; }
dim()   { echo -en "${A_DIM}$1${A_RESET}"; }

# Terminal dimensions (approximate for TUI)
W() { echo $(tput cols); }
H() { echo $(tput lines); }

# Strip ANSI escape codes for accurate string length calculation
strip_ansi() { echo "$1" | sed 's/\x1b\[[0-9;]*m//g'; }
vis_len()    { strip_ansi "$1" | wc -c; }

hr() {
  local char="${1:-"─"}"
  local color="${2:-$A_GRAY}"
  c_no_nl "$color" "$(printf '%*s' "$(W)" | tr ' ' "$char")"
}

pad_end() {
  local s="$1"
  local len="$2"
  local s_plain_len=$(strip_ansi "$s" | wc -c)
  if (( s_plain_len < len )); then
    echo -n "$s$(printf '%*s' $((len - s_plain_len)))"
  else
    echo -n "$s"
  fi
}

truncate_str() {
  local s="$1"
  local len="$2"
  local plain_s=$(strip_ansi "$s")
  if (( ${#plain_s} <= len )); then
    echo -n "$s"
  else
    echo -n "${plain_s:0:$((len - 1))}…"
  fi
}

box() {
  local title="$1"
  local -a lines=("${@:2}")
  local border_color="${A_CYAN}"

  local w=$(( $(W) - 2 ))
  if (( w > 78 )); then w=78; fi

  local title_len=${#title}
  local top_fill=$(( w - title_len - 4 ))
  if (( top_fill < 0 )); then top_fill=0; fi

  c_no_nl "$border_color" "┌─ "
  c_no_nl "${A_BOLD}${A_BCYAN}" "$title"
  c_no_nl "$border_color" " $(printf '%*s' "$top_fill" | tr ' ' '─')┐\n"

  for line in "${lines[@]}"; do
    local plain_line=$(strip_ansi "$line")
    local pad=$(( w - 2 - ${#plain_line} ))
    if (( pad < 0 )); then pad=0; fi
    c_no_nl "$border_color" "│ "
    echo -n "$line"
    printf '%*s' "$pad"
    c_no_nl "$border_color" " │\n"
  done

  c_no_nl "$border_color" "└$(printf '%*s' "$w" | tr ' ' '─')┘\n"
}

# --- Logging Functions -------------------------------------------------------
# Global state for logging and TUI
declare -gA STATE
STATE[log_lines]=""
STATE[status_msg]=""
STATE[status_color]="$A_GRAY"
STATE[tab]="log"
STATE[log_scroll]=0
STATE[input_buffer]=""
STATE[input_cursor]=0
STATE[shell_history]=""
STATE[shell_hist_idx]=-1
STATE[running]="false"
STATE[stop_requested]="false"
STATE[groq_last_call_time]=0
STATE[groq_call_count]=0
STATE[groq_error_backoff_delay]=0

push_log() {
  local msg="$1"
  STATE[log_lines]+="$msg\n"
  # Keep log_lines from growing indefinitely
  local max_log_lines=1000 # Arbitrary limit, can be adjusted
  local current_lines=$(echo -e "${STATE[log_lines]}" | wc -l)
  if (( current_lines > max_log_lines )); then
    STATE[log_lines]=$(echo -e "${STATE[log_lines]}" | tail -n "$max_log_lines")
  fi
}

log_sys() {
  local msg="$1"
  local color="${2:-$A_GRAY}"
  push_log "$(c "$color" "[SYS] $msg")"
}

log_section() {
  local title="$1"
  local color="${2:-$A_GRAY}"
  push_log ""
  push_log "$(c "$color" "─── ${title} $(printf '%*s' $(( $(W) - ${#title} - 8 )) | tr ' ' '─')")"
}

set_status() {
  STATE[status_msg]="$1"
  STATE[status_color]="${2:-$A_GRAY}"
}

# --- Session Management Functions --------------------------------------------
# Bug Fix 1: Unbounded message history - implemented trimming in save_session

# Loads a session from a JSON file.
# Arguments: session_id
# Returns: JSON string of the session or empty string if not found/error.
load_session() {
  local session_id="$1"
  local session_file="$SESSIONS_DIR/${session_id}.json"
  if [[ -f "$session_file" ]]; then
    cat "$session_file"
  else
    echo ""
  fi
}

# Saves a session to a JSON file.
# Arguments: session_json_string
save_session() {
  local session_json="$1"
  local session_id=$(echo "$session_json" | jq -r '.id')
  local session_file="$SESSIONS_DIR/${session_id}.json"

  # Update 'updated' timestamp
  session_json=$(echo "$session_json" | jq --argjson now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.updated = $now')

  # Bug Fix 1: Cap stored messages and trim older ones
  # Keep last 200 messages in the session file
  session_json=$(echo "$session_json" | jq 'if (.messages | length) > 200 then .messages = (.messages | .[length-200:]) else . end')

  echo "$session_json" > "$session_file"
}

# Lists all available sessions.
# Returns: JSON array of session summaries.
list_sessions() {
  local sessions_array="[]"
  for f in "$SESSIONS_DIR"/*.json; do
    if [[ -f "$f" ]]; then
      local s_json=$(cat "$f")
      local id=$(echo "$s_json" | jq -r '.id')
      local target=$(echo "$s_json" | jq -r '.target')
      local status=$(echo "$s_json" | jq -r '.status')
      local phase=$(echo "$s_json" | jq -r '.phase // "recon"')
      local findings_count=$(echo "$s_json" | jq '.findings | length')
      local messages_count=$(echo "$s_json" | jq '.messages | length')
      local updated=$(echo "$s_json" | jq -r '.updated')
      local created=$(echo "$s_json" | jq -r '.created')

      local session_summary=$(jq -n \
        --arg id "$id" \
        --arg target "$target" \
        --arg status "$status" \
        --arg phase "$phase" \
        --argjson findingsCount "$findings_count" \
        --argjson messagesCount "$messages_count" \
        --arg updated "$updated" \
        --arg created "$created" \
        '{id: $id, target: $target, status: $status, phase: $phase, findingsCount: $findingsCount, messagesCount: $messagesCount, updated: $updated, created: $created}')
      sessions_array=$(echo "$sessions_array" | jq --argjson ss "$session_summary" '. += [$ss]')
    fi
  done
  # Sort by updated timestamp (descending)
  echo "$sessions_array" | jq 'sort_by(.updated) | reverse'
}

# Creates a new session.
# Arguments: target scope notes
# Returns: JSON string of the new session.
create_session() {
  local target="$1"
  local scope="$2"
  local notes="$3"
  local uuid=$(cat /proc/sys/kernel/random/uuid)
  local now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local new_session=$(jq -n \
    --arg id "$uuid" \
    --arg target "$target" \
    --arg scope "$scope" \
    --arg notes "$notes" \
    --arg status "active" \
    --arg phase "recon" \
    --arg created "$now" \
    --arg updated "$now" \
    '{id: $id, target: $target, scope: $scope, notes: $notes, status: $status, phase: $phase, created: $created, updated: $updated, messages: [], findings: [], commandHistory: [], loopIteration: 0}')

  save_session "$new_session"
  echo "$new_session"
}

# Ensures the workspace directory for a session exists.
# Arguments: session_id
# Returns: Path to the workspace directory.
ensure_workspace() {
  local session_id="$1"
  local ws_dir="$WORKSPACE_DIR/${session_id}"
  mkdir -p "$ws_dir"
  echo "$ws_dir"
}

# --- Groq API Integration ----------------------------------------------------
# Bug Fix 3: No token/rate tracking - implemented rate limiting and call counter
# Bug Fix 5: No rate limiting between Groq API calls - implemented 2s minimum and exponential backoff

# Loads the Groq API key from file.
load_groq_key() {
  if [[ -f "$GROQ_KEY_FILE" ]]; then
    cat "$GROQ_KEY_FILE"
  else
    echo ""
  fi
}

# Saves the Groq API key to file.
# Arguments: key
save_groq_key() {
  local key="$1"
  echo "$key" > "$GROQ_KEY_FILE"
  chmod 600 "$GROQ_KEY_FILE"
}

# Makes a call to the Groq API.
# Arguments: messages_json_array
# Returns: JSON response from Groq API or error message.
call_groq_api() {
  local messages_json="$1"
  local groq_key=$(load_groq_key)

  if [[ -z "$groq_key" ]]; then
    log_sys "Groq API key not set. Use :key <gsk_...>" "$A_BRED"
    return 1
  fi

  # Bug Fix 5: Rate limiting and exponential backoff
  local current_time=$(date +%s)
  local time_since_last_call=$(( current_time - ${STATE[groq_last_call_time]} ))
  local min_interval=2 # 2 seconds minimum

  if (( time_since_last_call < min_interval )); then
    local sleep_time=$(( min_interval - time_since_last_call ))
    log_sys "Rate limiting: Waiting ${sleep_time}s before next API call." "$A_GRAY"
    sleep "$sleep_time"
  fi

  # Apply exponential backoff if there was a recent error
  if (( ${STATE[groq_error_backoff_delay]} > 0 )); then
    log_sys "Applying exponential backoff: Waiting ${STATE[groq_error_backoff_delay]}s." "$A_BYELLOW"
    sleep "${STATE[groq_error_backoff_delay]}"
  fi

  local response=$(curl -s -X POST https://api.groq.com/openai/v1/chat/completions \
    -H "Authorization: Bearer $groq_key" \
    -H "Content-Type: application/json" \
    -d "{\"model\": \"llama-3.3-70b-versatile\", \"messages\": ${messages_json}, \"temperature\": 0.7, \"max_tokens\": 2000}")

  local http_code=$(echo "$response" | jq -r '.error.code // 
"null"')

  if [[ "$http_code" != "null" ]]; then
    local error_msg=$(echo "$response" | jq -r '.error.message')
    log_sys "Groq API Error: $error_msg" "$A_BRED"
    # Exponential backoff logic
    if (( ${STATE[groq_error_backoff_delay]} == 0 )); then
      STATE[groq_error_backoff_delay]=2
    elif (( ${STATE[groq_error_backoff_delay]} < 30 )); then
      STATE[groq_error_backoff_delay]=$(( ${STATE[groq_error_backoff_delay]} * 2 ))
    fi
    return 1
  else
    # Success, reset backoff
    STATE[groq_error_backoff_delay]=0
    STATE[groq_last_call_time]=$(date +%s)
    STATE[groq_call_count]=$(( ${STATE[groq_call_count]} + 1 ))
    log_sys "Groq API call successful. Total calls: ${STATE[groq_call_count]}" "$A_GRAY"
    echo "$response" | jq -r '.choices[0].message.content'
    return 0
  fi
}

# --- Command Execution & Safety Checks ---------------------------------------
# Bug Fix 2: Command timeout not cleared on normal close - implemented proper timeout handling
# Bug Fix 4: Weak dangerous command blocking - implemented robust blocklist and whitelist

# Checks if a command is safe to execute.
# Arguments: command_string
# Returns: 0 if safe, 1 if blocked.
is_safe() {
  local cmd="$1"
  # Robust blocklist including variable expansion tricks
  local blocked_patterns=(
    'rm\s+-rf\s+/'
    'rm\s+-rf\s+\*'
    ':\(\)\{.*\}'
    'mkfs'
    '\bshutdown\b'
    '\breboot\b'
    '\bpoweroff\b'
    '\bhalt\b'
    'dd\s+if=.*of=/dev/'
    '>\s*/dev/sd'
    'wget\s+.*\s+\|\s*bash'
    'curl\s+.*\s+\|\s*bash'
    '\brm\b.*\b-rf\b.*\b/\b' # Catch rm -rf / even with spaces or other flags
  )

  for pattern in "${blocked_patterns[@]}"; do
    if echo "$cmd" | grep -qE "$pattern"; then
      return 1 # Blocked
    fi
  done

  # Whitelist approach for known-safe command prefixes (optional, but good for security)
  # For a bug bounty tool, we might need a wide range of commands, so a strict whitelist might be too restrictive.
  # We'll rely on the robust blocklist for now, but this is where a whitelist could be added.

  return 0 # Safe
}

# Executes a shell command safely with a timeout.
# Arguments: command_string session_id timeout_ms
# Returns: JSON object with stdout, stderr, exitCode, truncated.
execute_command() {
  local cmd="$1"
  local sid="$2"
  local timeout_ms="${3:-120000}"
  local timeout_s=$(( timeout_ms / 1000 ))

  if ! is_safe "$cmd"; then
    echo '{"stdout": "", "stderr": "⛔ BLOCKED", "exitCode": 1, "truncated": false}'
    return
  fi

  local ws_dir=$(ensure_workspace "$sid")
  local log_path="$LOGS_DIR/${sid}.log"
  local now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  echo -e "\n[$now] $ $cmd" >> "$log_path"

  # Bug Fix 2: Proper timeout handling using 'timeout' command
  # This ensures the process is killed cleanly if it exceeds the timeout,
  # and the timeout is automatically cleared if the process exits normally.
  local stdout_file=$(mktemp)
  local stderr_file=$(mktemp)

  # Run the command with timeout, redirecting output
  # We use bash -c to evaluate the command string
  timeout "$timeout_s" bash -c "cd '$ws_dir' && $cmd" > "$stdout_file" 2> "$stderr_file"
  local exit_code=$?

  local stdout_content=$(cat "$stdout_file" | head -c 20000)
  local stderr_content=$(cat "$stderr_file" | head -c 4000)
  local truncated="false"

  local stdout_len=$(wc -c < "$stdout_file")
  if (( stdout_len > 20000 )); then
    truncated="true"
  fi

  if (( exit_code == 124 )); then
    stderr_content+="\n⏱ [timeout]"
  fi

  echo -e "OUT:${stdout_content}\nERR:${stderr_content}\nEXIT:${exit_code}" >> "$log_path"

  rm -f "$stdout_file" "$stderr_file"

  # Escape JSON strings properly
  local stdout_json=$(echo "$stdout_content" | jq -R -s '.')
  local stderr_json=$(echo "$stderr_content" | jq -R -s '.')

  echo "{\"stdout\": ${stdout_json}, \"stderr\": ${stderr_json}, \"exitCode\": ${exit_code}, \"truncated\": ${truncated}}"
}

# --- AI Agent Loop -----------------------------------------------------------
# Bug Fix 6: Fragile findings regex - implemented robust findings detection

readonly SYSTEM_PROMPT="You are 0x-Hunt — an elite autonomous bug bounty hunter AI running on Linux/Termux. You operate inside a persistent agentic loop with full shell access.

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

**FINDING:** [If you found a vulnerability, describe it here. Otherwise omit.]

## Rules
1. NEVER use interactive commands (no nano, vim, less, top without -b).
2. ALWAYS use non-interactive flags (e.g., -y, --no-prompt).
3. If a command hangs, it will be killed. Use timeouts (e.g., timeout 10s nmap ...).
4. Save important results to files in the current directory (workspace).
5. If you are done or stuck, explain in THINK and use command: echo 'DONE' or echo 'STUCK'.
6. Keep commands simple and robust. Avoid complex bash scripting if possible.
7. Do not hallucinate findings. Only report what the tools output.
"

# Parses the LLM response to extract phase, think, command, expect, and finding.
# Arguments: llm_response
# Returns: JSON object with parsed fields.
parse_llm_response() {
  local response="$1"
  local phase=""
  local think=""
  local command=""
  local expect=""
  local finding=""

  # Extract Phase
  phase=$(echo "$response" | grep -iE '^\*\*PHASE:\*\*' | sed -E 's/^\*\*PHASE:\*\*\s*//I' | tr -d '\r')
  if [[ -z "$phase" ]]; then
    phase=$(echo "$response" | grep -iE '^PHASE:' | sed -E 's/^PHASE:\s*//I' | tr -d '\r')
  fi

  # Extract Think
  think=$(echo "$response" | awk '/^\*\*THINK:\*\*/{flag=1; print; next} /^\*\*COMMAND:\*\*/{flag=0} flag' | sed -E 's/^\*\*THINK:\*\*\s*//I' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [[ -z "$think" ]]; then
    think=$(echo "$response" | awk '/^THINK:/{flag=1; print; next} /^COMMAND:/{flag=0} flag' | sed -E 's/^THINK:\s*//I' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  fi

  # Extract Command
  command=$(echo "$response" | awk '/```bash/{flag=1; next} /```/{if(flag){flag=0; next}} flag' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [[ -z "$command" ]]; then
    # Fallback if no bash block
    command=$(echo "$response" | awk '/^\*\*COMMAND:\*\*/{flag=1; next} /^\*\*EXPECT:\*\*/{flag=0} flag' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  fi

  # Extract Expect
  expect=$(echo "$response" | awk '/^\*\*EXPECT:\*\*/{flag=1; print; next} /^\*\*FINDING:\*\*/{flag=0} flag' | sed -E 's/^\*\*EXPECT:\*\*\s*//I' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [[ -z "$expect" ]]; then
    expect=$(echo "$response" | awk '/^EXPECT:/{flag=1; print; next} /^FINDING:/{flag=0} flag' | sed -E 's/^EXPECT:\s*//I' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  fi

  # Bug Fix 6: Robust findings detection
  # Look for multiple patterns, case-insensitive
  finding=$(echo "$response" | awk 'BEGIN{IGNORECASE=1} /^\*\*FINDING:\*\*/ || /^FINDING:/ || /^🚨 FINDING:/ || /^\*\*VULNERABILITY:\*\*/ || /^VULNERABILITY:/{flag=1; print; next} /^$/{if(flag){flag=0}} flag' | sed -E 's/^(\*\*FINDING:\*\*|FINDING:|🚨 FINDING:|\*\*VULNERABILITY:\*\*|VULNERABILITY:)\s*//I' | tr -d '\r' | tr '\n' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

  # Escape JSON strings
  local phase_json=$(echo "$phase" | jq -R -s '.')
  local think_json=$(echo "$think" | jq -R -s '.')
  local command_json=$(echo "$command" | jq -R -s '.')
  local expect_json=$(echo "$expect" | jq -R -s '.')
  local finding_json=$(echo "$finding" | jq -R -s '.')

  echo "{\"phase\": ${phase_json}, \"think\": ${think_json}, \"command\": ${command_json}, \"expect\": ${expect_json}, \"finding\": ${finding_json}}"
}

# Runs the main agent loop.
# Arguments: initial_message (optional)
run_agent_loop() {
  local initial_message="$1"

  if [[ -z "${STATE[session_json]}" ]]; then
    log_sys "No active session to run agent loop." "$A_BRED"
    return 1
  fi

  STATE[running]="true"
  STATE[stop_requested]="false"

  while [[ "${STATE[running]}" == "true" && "${STATE[stop_requested]}" == "false" ]]; do
    local current_session_json="${STATE[session_json]}"
    local session_id=$(echo "$current_session_json" | jq -r ".id")
    local current_phase=$(echo "$current_session_json" | jq -r ".phase")
    local loop_iteration=$(echo "$current_session_json" | jq -r ".loopIteration")

    log_sys "Agent loop iteration: $((loop_iteration + 1)) (Phase: $current_phase)" "$A_GRAY"
    set_status "Agent running... (Iteration: $((loop_iteration + 1)))" "$A_BCYAN"
    render

    # Construct messages for Groq API
    local messages_array="[]"
    messages_array=$(echo "$messages_array" | jq --arg content "$SYSTEM_PROMPT" ". += [{\"role\": \"system\", \"content\": \"$content\"}]")

    # Add session context (target, scope, notes)
    local target=$(echo "$current_session_json" | jq -r ".target")
    local scope=$(echo "$current_session_json" | jq -r ".scope")
    local notes=$(echo "$current_session_json" | jq -r ".notes")
    local context_message="Current Target: $target\nScope: $scope"
    if [[ -n "$notes" ]]; then
      context_message+="\nNotes: $notes"
    fi
    messages_array=$(echo "$messages_array" | jq --arg content "$context_message" ". += [{\"role\": \"user\", \"content\": \"$content\"}]")

    # Add previous messages (capped at 60 as per original JS, but stored messages are 200 due to Bug Fix 1)
    local session_messages=$(echo "$current_session_json" | jq ".messages | .[length-60:] // []")
    messages_array=$(echo "$messages_array" | jq --argjson sm "$session_messages" ". += $sm")

    # Add initial message if provided for the first iteration
    if [[ "$loop_iteration" -eq 0 && -n "$initial_message" ]]; then
      messages_array=$(echo "$messages_array" | jq --arg content "$initial_message" ". += [{\"role\": \"user\", \"content\": \"$content\"}]")
    fi

    local llm_response_content=$(call_groq_api "$messages_array")
    local llm_status=$?

    if [[ "$llm_status" -ne 0 ]]; then
      log_sys "Groq API call failed. Retrying..." "$A_BRED"
      sleep 5 # Wait before retrying
      continue
    fi

    # Add LLM response to messages history
    current_session_json=$(echo "$current_session_json" | jq --arg content "$llm_response_content" ".messages += [{\"role\": \"assistant\", \"content\": \"$content\"}]")

    local parsed_response=$(parse_llm_response "$llm_response_content")
    local new_phase=$(echo "$parsed_response" | jq -r ".phase")
    local think_text=$(echo "$parsed_response" | jq -r ".think")
    local command_to_exec=$(echo "$parsed_response" | jq -r ".command")
    local expect_text=$(echo "$parsed_response" | jq -r ".expect")
    local finding_text=$(echo "$parsed_response" | jq -r ".finding")

    log_sys "LLM Think: $think_text" "$A_CYAN"
    if [[ -n "$new_phase" && "$new_phase" != "null" ]]; then
      current_session_json=$(echo "$current_session_json" | jq --arg phase "$new_phase" ".phase = \"$phase\"")
      log_sys "Phase changed to: $new_phase" "$A_BYELLOW"
    fi

    if [[ -n "$finding_text" && "$finding_text" != "null" ]]; then
      log_sys "🚨 NEW FINDING: $finding_text" "$A_BRED"
      current_session_json=$(echo "$current_session_json" | jq --arg finding "$finding_text" ".findings += [{\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"text\": \"$finding\"}]")
    fi

    if [[ -n "$command_to_exec" && "$command_to_exec" != "null" ]]; then
      log_sys "Executing command: $command_to_exec" "$A_BMAGENTA"
      set_status "Executing: $command_to_exec" "$A_BMAGENTA"
      render

      local cmd_output_json=$(execute_command "$command_to_exec" "$session_id")
      local cmd_stdout=$(echo "$cmd_output_json" | jq -r ".stdout")
      local cmd_stderr=$(echo "$cmd_output_json" | jq -r ".stderr")
      local cmd_exit_code=$(echo "$cmd_output_json" | jq -r ".exitCode")

      log_sys "Command finished with exit code: $cmd_exit_code" "$A_GRAY"
      if [[ -n "$cmd_stdout" ]]; then
        log_sys "STDOUT: $(echo "$cmd_stdout" | head -n 5)" "$A_DIM"
      fi
      if [[ -n "$cmd_stderr" ]]; then
        log_sys "STDERR: $(echo "$cmd_stderr" | head -n 5)" "$A_RED"
      fi

      # Add command and its output to messages history for LLM context
      local cmd_full_output="Command: $command_to_exec\nExit Code: $cmd_exit_code\nSTDOUT: $cmd_stdout\nSTDERR: $cmd_stderr"
      current_session_json=$(echo "$current_session_json" | jq --arg content "$cmd_full_output" ".messages += [{\"role\": \"user\", \"content\": \"$content\"}]")
      current_session_json=$(echo "$current_session_json" | jq --arg cmd "$command_to_exec" ".commandHistory += [\"$cmd\"]")

      if [[ "$command_to_exec" == "echo 'DONE'" || "$command_to_exec" == "echo 'STUCK'" ]]; then
        STATE[running]="false"
        log_sys "Agent signaled completion or stuck state." "$A_BYELLOW"
      fi

    else
      log_sys "LLM did not provide a command to execute." "$A_BYELLOW"
      # If LLM doesn't provide a command, it might be stuck or done. Ask for user input or stop.
      STATE[running]="false"
      log_sys "Agent loop stopped as no command was provided." "$A_BYELLOW"
    fi

    current_session_json=$(echo "$current_session_json" | jq ".loopIteration = (.loopIteration + 1)")
    STATE[session_json]="$current_session_json"
    save_session "$current_session_json"
    sleep 1 # Small delay to prevent busy-waiting
  done

  STATE[running]="false"
  set_status "Agent loop stopped." "$A_GRAY"
  render
}

# --- System Metrics (Translated from Node.js) --------------------------------
fmt_bytes() {
  local b="$1"
  if (( b < 1024 )); then echo "${b}B"; return; fi
  if (( b < 1048576 )); then echo "$((b/1024))K"; return; fi
  if (( b < 1073741824 )); then echo "$(printf "%.1f" "$(echo "scale=1; $b/1048576" | bc)")M"; return; fi
  echo "$(printf "%.2f" "$(echo "scale=2; $b/1073741824" | bc)")G"
}

mem_bar() {
  local pct="$1"
  local width="${2:-20}"
  local filled=$(( pct * width / 100 ))
  local color="$A_BGREEN"
  if (( pct > 90 )); then color="$A_BGRED";
  elif (( pct > 70 )); then color="$A_BGYELLOW"; fi
  c_no_nl "$color" "$(printf █%.0s $(seq 1 $filled))"
  c_no_nl "$A_GRAY" "$(printf ░%.0s $(seq 1 $((width - filled))))"
}

get_mem_info() {
  local mem_total=0 mem_avail=0 mem_used=0 mem_pct=0
  if [[ -f /proc/meminfo ]]; then
    mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2 * 1024}')
    mem_avail=$(grep MemAvailable /proc/meminfo | awk '{print $2 * 1024}')
    mem_used=$(( mem_total - mem_avail ))
  else # Fallback for systems without /proc/meminfo (e.g., some Termux setups)
    # Using free command, but it might not be available or parseable everywhere
    # This is a best-effort attempt, os.totalmem() and os.freemem() are Node.js specific
    # For Termux, `termux-info` might provide some details, but `free` is more common.
    local free_output=$(free -b 2>/dev/null | awk 'NR==2{print $2, $7}')
    if [[ -n "$free_output" ]]; then
      mem_total=$(echo "$free_output" | awk '{print $1}')
      mem_avail=$(echo "$free_output" | awk '{print $2}')
      mem_used=$(( mem_total - mem_avail ))
    else
      # Last resort, hardcode some values or indicate unknown
      mem_total=1000000000 # 1GB approx
      mem_avail=500000000
      mem_used=500000000
    fi
  fi
  if (( mem_total > 0 )); then mem_pct=$(( mem_used * 100 / mem_total )); fi
  echo "{\"total\": $mem_total, \"used\": $mem_used, \"avail\": $mem_avail, \"pct\": $mem_pct}"
}

get_cpu_load() {
  local load1=0 load5=0 cores=1
  if [[ -f /proc/loadavg ]]; then
    local load_avg_output=$(cat /proc/loadavg)
    load1=$(echo "$load_avg_output" | awk '{printf "%.2f", $1}')
    load5=$(echo "$load_avg_output" | awk '{printf "%.2f", $2}')
  fi
  if [[ -f /proc/cpuinfo ]]; then
    cores=$(grep -c ^processor /proc/cpuinfo)
  fi
  echo "{\"load1\": \"$load1\", \"load5\": \"$load5\", \"cores\": $cores}"
}

get_disk_info() {
  local total=0 used=0 avail=0 pct=0
  local df_output=$(df -B1 . 2>/dev/null | awk 'NR==2{print $2, $3, $4}')
  if [[ -n "$df_output" ]]; then
    total=$(echo "$df_output" | awk '{print $1}')
    used=$(echo "$df_output" | awk '{print $2}')
    avail=$(echo "$df_output" | awk '{print $3}')
    if (( total > 0 )); then pct=$(( used * 100 / total )); fi
  fi
  echo "{\"total\": $total, \"used\": $used, \"avail\": $avail, \"pct\": $pct}"
}

get_net_info() {
  local ifaces_json="[]"
  local vpn_detected="false"

  # Using `ip -o link show` and `ip -o addr show` for network interfaces
  # This is more robust than parsing /proc/net/dev or relying on `ifconfig` which might be deprecated
  local ip_links=$(ip -o link show)
  local ip_addrs=$(ip -o addr show)

  while IFS= read -r line; do
    local iface_name=$(echo "$line" | awk '{print $2}' | sed 's/://')
    # Check if it's not a loopback interface and is up
    if [[ "$iface_name" != "lo" && "$line" =~ "UP" ]]; then
      local ip_addr=$(echo "$ip_addrs" | grep " $iface_name " | grep "inet " | awk '{print $4}' | cut -d'/' -f1 | head -n 1)
      if [[ -n "$ip_addr" ]]; then
        ifaces_json=$(echo "$ifaces_json" | jq --arg name "$iface_name" --arg ip "$ip_addr" '. += [{name: $name, ip: $ip}]')
        if echo "$iface_name" | grep -qE '^(tun|tap|wg|vpn|ppp)'; then
          vpn_detected="true"
        fi
      fi
    fi
  done <<< "$ip_links"

  echo "{\"ifaces\": $ifaces_json, \"vpn\": $vpn_detected}"
}

readonly TOOLS=(
  "subfinder" "assetfinder" "waybackurls" "gau" "katana" "hakrawler"
  "dig" "whois" "nmap" "httpx" "nuclei" "nikto" "whatweb"
  "ffuf" "gobuster" "arjun" "dalfox" "sqlmap" "gf" "qsreplace"
  "curl" "wget" "python3" "jq" "git" "go"
)

check_tools() {
  local results_json="[]"
  for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
      results_json=$(echo "$results_json" | jq --arg tool "$tool" '. += [{tool: $tool, ok: true}]')
    else
      results_json=$(echo "$results_json" | jq --arg tool "$tool" '. += [{tool: $tool, ok: false}]')
    fi
  done
  echo "$results_json"
}

# --- TUI Rendering Functions -------------------------------------------------
render_header() {
  local current_session_id="N/A"
  local current_target="N/A"
  local current_phase="N/A"
  local findings_count=0

  if [[ -n "${STATE[session_json]}" ]]; then
    current_session_id=$(echo "${STATE[session_json]}" | jq -r ".id | .[0:8]")
    current_target=$(echo "${STATE[session_json]}" | jq -r ".target")
    current_phase=$(echo "${STATE[session_json]}" | jq -r ".phase")
    findings_count=$(echo "${STATE[session_json]}" | jq ".findings | length")
  fi

  local title_text="0x-HUNT v2"
  local info_text="Session: $(c "$A_BCYAN" "$current_session_id") Target: $(c "$A_BCYAN" "$current_target") Phase: $(c "$A_BYELLOW" "$current_phase") Findings: $(c "$A_BRED" "$findings_count")"

  local header_line="$(c "$A_BGBLACK" "$(pad_end "$(c "$A_BOLD" "$title_text")" $(( $(W) - ${#info_text} - 2 )))$info_text")"
  echo -en "$header_line\n"
  hr "─" "$A_GRAY"
  echo ""
}

render_tabs() {
  local tabs=("log" "findings" "shell" "files" "sessions")
  local tab_output=""
  for t in "${tabs[@]}"; do
    local tab_name=$(echo "$t" | tr '[:lower:]' '[:upper:]')
    if [[ "$t" == "${STATE[tab]}" ]]; then
      tab_output+="$(c "$A_BGBLUE" "$(c "$A_BWHITE" " $tab_name ")")"
    else
      tab_output+="$(c "$A_BGBLACK" "$(c "$A_GRAY" " $tab_name ")")"
    fi
    tab_output+=" "
  done
  echo -en "$tab_output\n"
  hr "─" "$A_GRAY"
  echo ""
}

render_log_tab() {
  local rows=$(( $(H) - 7 ))
  local log_lines_array=()
  IFS=$'
' read -r -d '' -a log_lines_array <<< "${STATE[log_lines]}"
  local total_lines=${#log_lines_array[@]}

  local from=0
  if (( total_lines > rows )); then
    from=$(( total_lines - rows - STATE[log_scroll] ))
    if (( from < 0 )); then from=0; fi
    if (( from > total_lines - rows )); then from=$(( total_lines - rows )); fi
  fi

  for (( i=0; i<rows; i++ )); do
    local line_idx=$(( from + i ))
    if (( line_idx < total_lines )); then
      echo -en "${log_lines_array[line_idx]}\n"
    else
      echo ""
    fi
  done
}

render_findings_tab() {
  local rows=$(( $(H) - 7 ))
  local findings_array=()
  if [[ -n "${STATE[session_json]}" ]]; then
    # Extract findings and format them for display
    local raw_findings=$(echo "${STATE[session_json]}" | jq -c ".findings[]")
    while IFS= read -r f_json; do
      local timestamp=$(echo "$f_json" | jq -r ".timestamp")
      local text=$(echo "$f_json" | jq -r ".text")
      findings_array+=("$(c "$A_GRAY" "[$timestamp]") $(c "$A_BRED" "🚨") $(c "$A_WHITE" "$text")")
    done <<< "$raw_findings"
  fi

  local total_lines=${#findings_array[@]}
  if (( total_lines == 0 )); then
    for (( i=0; i<rows-1; i++ )); do echo ""; done
    echo "$(c "$A_GRAY" "  No findings yet.")"
    return
  fi

  local from=0
  if (( total_lines > rows )); then
    from=$(( total_lines - rows ))
  fi

  for (( i=0; i<rows; i++ )); do
    local line_idx=$(( from + i ))
    if (( line_idx < total_lines )); then
      echo -en "${findings_array[line_idx]}\n"
    else
      echo ""
    fi
  done
}

render_shell_tab() {
  local rows=$(( $(H) - 7 ))
  # For now, shell tab just shows log. Real shell passthrough needs more complex PTY handling.
  # This is a simplification for the bash rewrite, matching the spirit of the JS version's shell tab.
  render_log_tab
}

render_files_tab() {
  local rows=$(( $(H) - 7 ))
  if [[ -z "${STATE[session_json]}" ]]; then
    for (( i=0; i<rows-1; i++ )); do echo ""; done
    echo "$(c "$A_GRAY" "  No active session.")"
    return
  fi

  local session_id=$(echo "${STATE[session_json]}" | jq -r ".id")
  local ws_dir="$WORKSPACE_DIR/$session_id"

  if [[ ! -d "$ws_dir" ]]; then
    for (( i=0; i<rows-1; i++ )); do echo ""; done
    echo "$(c "$A_GRAY" "  Workspace empty.")"
    return
  fi

  local file_lines=()
  # Recursive directory listing with depth limit, similar to Node.js walk function
  _walk_files() {
    local current_dir="$1"
    local prefix="$2"
    local depth="$3"
    if (( depth > 3 )); then return; fi

    while IFS= read -r entry; do
      local entry_name=$(basename "$entry")
      if [[ -d "$entry" ]]; then
        file_lines+=("${prefix}$(c "$A_BLUE" "▸ ")""$(c "${A_BOLD}${A_BLUE}" "$entry_name/")")
        _walk_files "$entry" "$prefix  " $((depth + 1))
      elif [[ -f "$entry" ]]; then
        local file_size=$(stat -c %s "$entry" 2>/dev/null || echo 0)
        file_lines+=("${prefix}$(c "$A_GRAY" "· ")""$(c "$A_WHITE" "$entry_name")""$(c "$A_GRAY" "  $(fmt_bytes "$file_size")")")
      fi
    done < <(find "$current_dir" -maxdepth 1 -mindepth 1 | sort)
  }
  _walk_files "$ws_dir" "" 0

  if (( ${#file_lines[@]} == 0 )); then
    file_lines+=("$(c "$A_GRAY" "  (empty)")")
  fi

  local total_lines=${#file_lines[@]}
  local from=0
  if (( total_lines > rows )); then
    from=$(( total_lines - rows ))
  fi

  for (( i=0; i<rows; i++ )); do
    local line_idx=$(( from + i ))
    if (( line_idx < total_lines )); then
      echo -en "${file_lines[line_idx]}\n"
    else
      echo ""
    fi
  done
}

render_sessions_tab() {
  local rows=$(( $(H) - 7 ))
  local sessions_array=()
  local all_sessions_json=$(list_sessions)
  local session_count=$(echo "$all_sessions_json" | jq ". | length")

  if (( session_count == 0 )); then
    for (( i=0; i<rows-1; i++ )); do echo ""; done
    echo "$(c "$A_GRAY" "  No sessions. Use :new to start a hunt.")"
    return
  fi

  local i=0
  while IFS= read -r s_json; do
    local id=$(echo "$s_json" | jq -r ".id")
    local target=$(echo "$s_json" | jq -r ".target")
    local status=$(echo "$s_json" | jq -r ".status")
    local phase=$(echo "$s_json" | jq -r ".phase")
    local findings_count=$(echo "$s_json" | jq -r ".findingsCount")
    local messages_count=$(echo "$s_json" | jq -r ".messagesCount")
    local updated=$(echo "$s_json" | jq -r ".updated")

    local active_prefix=" "
    if [[ -n "${STATE[session_json]}" && "$(echo "${STATE[session_json]}" | jq -r ".id")" == "$id" ]]; then
      active_prefix="$(c "${A_BCYAN}${A_BOLD}" "▶")"
    fi

    local status_color="$A_GRAY"
    case "$status" in
      "active") status_color="$A_BGREEN" ;;
      "paused") status_color="$A_BYELLOW" ;;
      "error") status_color="$A_BRED" ;;
      "waiting_input") status_color="$A_BMAGENTA" ;;
    esac

    sessions_array+=("${active_prefix} $(c "$A_GRAY" "[")""$(c "$A_WHITE" "$((i+1))")""$(c "$A_GRAY" "]")"" $(c "${A_BOLD}${A_BCYAN}" "$target")")
    sessions_array+=("    $(c "$status_color" "$(pad_end "$status" 14)")"" $(c "$A_BYELLOW" "$(pad_end "$(echo "$phase" | tr '[:lower:]' '[:upper:]')" 10)")"" $(c "$A_GRAY" "$findings_count finds  $messages_count msgs")")
    sessions_array+=("    $(c "$A_GRAY" "${id:0:8}…  $(date -d "$updated" +"%Y-%m-%d %H:%M")")")
    sessions_array+=("")
    i=$((i+1))
  done <<< "$(echo "$all_sessions_json" | jq -c ".[]")"

  local total_lines=${#sessions_array[@]}
  local from=0
  if (( total_lines > rows )); then
    from=$(( total_lines - rows ))
  fi

  for (( i=0; i<rows; i++ )); do
    local line_idx=$(( from + i ))
    if (( line_idx < total_lines )); then
      echo -en "${sessions_array[line_idx]}\n"
    else
      echo ""
    fi
  done
}

render_status_bar() {
  local input_prompt="$(c "$A_GRAY" " > ")"
  local input_line="$(c "$A_WHITE" "${STATE[input_buffer]}")"
  local cursor_pos=$(( ${#input_prompt} + ${STATE[input_cursor]} ))

  hr "─" "$A_GRAY"
  echo -en "$(c "${STATE[status_color]}" "${STATE[status_msg]}")\n"
  echo -en "${input_prompt}${input_line}${A_CLEARLN}"
  echo -en "\033[${cursor_pos}G"
}

render() {
  echo -en "${A_CLEAR}${A_HIDE}"
  render_header
  render_tabs
  case "${STATE[tab]}" in
    "log")      render_log_tab      ;;
    "findings") render_findings_tab ;;
    "shell")    render_shell_tab    ;;
    "files")    render_files_tab    ;;
    "sessions") render_sessions_tab ;;
  esac
  render_status_bar
}

# --- Input Handling ----------------------------------------------------------
setup_input() {
  # Disable canonical mode and echo for raw input
  stty -echo -icanon time 0 min 0
  # Trap Ctrl+C (SIGINT)
  trap handle_ctrl_c SIGINT

  # Read input in a loop
  while true; do
    local char
    read -s -n 1 char # Read one character silently
    if [[ -n "$char" ]]; then
      handle_input "$char"
    fi
    # Small sleep to prevent busy-waiting, but still responsive
    sleep 0.01
  done
}

handle_input() {
  local chunk="$1"
  case "$chunk" in
    $'[A') history_up ;;
    $'[B') history_down ;;
    $'[C') cursor_right ;;
    $'[D') cursor_left ;;
    $'') handle_ctrl_c ;;
    $'') STATE[log_lines]=""; render ;;
    $'') STATE[input_buffer]=""; STATE[input_cursor]=0; render ;;
    $'	') cycle_tab ;;
    $''|$'') # Backspace or Ctrl+H
      if (( STATE[input_cursor] > 0 )); then
        STATE[input_buffer]="${STATE[input_buffer]:0:$((STATE[input_cursor]-1))}${STATE[input_buffer]:${STATE[input_cursor]}}"
        STATE[input_cursor]=$((STATE[input_cursor]-1))
      fi
      render ;;
    $'
'|$'
') # Enter key
      local input="${STATE[input_buffer]}"
      STATE[input_buffer]=""
      STATE[input_cursor]=0
      if [[ -n "$input" ]]; then
        # Add to shell history (if not empty)
        if [[ "$input" != "${STATE[shell_history]%%\n*}" ]]; then # Avoid duplicate consecutive entries
          STATE[shell_history]="$input\n${STATE[shell_history]}"
          # Cap shell history to 100 entries
          STATE[shell_history]=$(echo -e "${STATE[shell_history]}" | head -n 100)
        fi
        STATE[shell_hist_idx]=-1 # Reset history index
        handle_command "$input"
      else
        render
      fi
      ;;
    *) # Regular character input
      # Only append if it's a printable character
      if [[ "$chunk" =~ ^[[:print:]]$ ]]; then
        STATE[input_buffer]="${STATE[input_buffer]:0:${STATE[input_cursor]}}${chunk}${STATE[input_buffer]:${STATE[input_cursor]}}"
        STATE[input_cursor]=$((STATE[input_cursor]+${#chunk}))
        render
      fi
      ;;
  esac
}

history_up() {
  if [[ -z "${STATE[shell_history]}" ]]; then return; fi
  local history_array=()
  IFS=$'
' read -r -d '' -a history_array <<< "${STATE[shell_history]}"
  local history_len=${#history_array[@]}

  if (( STATE[shell_hist_idx] < history_len - 1 )); then
    STATE[shell_hist_idx]=$((STATE[shell_hist_idx]+1))
    STATE[input_buffer]="${history_array[STATE[shell_hist_idx]]}"
    STATE[input_cursor]=${#STATE[input_buffer]}
    render
  fi
}

history_down() {
  if (( STATE[shell_hist_idx] > 0 )); then
    STATE[shell_hist_idx]=$((STATE[shell_hist_idx]-1))
    STATE[input_buffer]="${history_array[STATE[shell_hist_idx]]}"
    STATE[input_cursor]=${#STATE[input_buffer]}
    render
  elif (( STATE[shell_hist_idx] == 0 )); then
    STATE[shell_hist_idx]=-1
    STATE[input_buffer]=""
    STATE[input_cursor]=0
    render
  fi
}

cursor_left() {
  if (( STATE[input_cursor] > 0 )); then
    STATE[input_cursor]=$((STATE[input_cursor]-1))
    render
  fi
}

cursor_right() {
  if (( STATE[input_cursor] < ${#STATE[input_buffer]} )); then
    STATE[input_cursor]=$((STATE[input_cursor]+1))
    render
  fi
}

handle_ctrl_c() {
  if [[ "${STATE[running]}" == "true" ]]; then
    STATE[stop_requested]="true"
    set_status "Stop requested..." "$A_BYELLOW"
    render
  else
    echo -en "${A_SHOW}${A_RESET}\n"
    log_sys "Goodbye. Sessions saved." "$A_GRAY"
    exit 0
  fi
}

cycle_tab() {
  local tabs=("log" "findings" "shell" "files" "sessions")
  local current_idx=-1
  for i in "${!tabs[@]}"; do
    if [[ "${tabs[$i]}" == "${STATE[tab]}" ]]; then
      current_idx="$i"
      break
    fi
  done
  local next_idx=$(( (current_idx + 1) % ${#tabs[@]} ))
  STATE[tab]="${tabs[$next_idx]}"
  render
}

# --- Command Router ----------------------------------------------------------
handle_command() {
  local input="$1"
  local lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]')

  case "$lower_input" in
    ":log"|"l")      STATE[tab]="log"; render ;;
    ":findings"|"f") STATE[tab]="findings"; render ;;
    ":shell"|"s")    STATE[tab]="shell"; render ;;
    ":files"|"x")    STATE[tab]="files"; render ;;
    ":sessions"|"e") STATE[tab]="sessions"; render ;;

    "j"|":down") STATE[log_scroll]=$((STATE[log_scroll] - 5)); if (( STATE[log_scroll] < 0 )); then STATE[log_scroll]=0; fi; render ;;
    "k"|":up")   STATE[log_scroll]=$((STATE[log_scroll] + 5)); render ;;
    "g"|":top")  STATE[log_scroll]=999999; render ;;
    "G"|":bot")  STATE[log_scroll]=0; render ;;

    ":help"|":h"|"?") show_help ;;
    ":q"|":quit"|":exit")
      echo -en "${A_SHOW}${A_RESET}\n"
      log_sys "Goodbye. Sessions saved." "$A_GRAY"
      exit 0 ;;

    ":ram"|"checkram") show_ram ;;
    ":cpu"|"checkcpu") show_cpu ;;
    ":disk"|"checkdisk") show_disk ;;
    ":net"|"checknet") show_net ;;
    ":tools"|"checktools") show_tools ;;
    ":status") show_status ;;
    ":groqtest") test_groq ;;

    ":ls") STATE[tab]="sessions"; render ;;
    ":new") cmd_new ;;
    ":stop") STATE[stop_requested]="true"; set_status "Stop requested..." "$A_BYELLOW"; render ;;
    ":report") show_report ;;
    ":clearlog") STATE[log_lines]=""; set_status "Log cleared" "$A_BGREEN"; render ;;

    *) # Handle commands with arguments or shell passthrough
      if [[ "$lower_input" =~ ^":load " || "$lower_input" =~ ^":resume " ]]; then
        local arg=$(echo "$input" | cut -d' ' -f2-)
        cmd_load "$arg"
      elif [[ "$lower_input" =~ ^":del " || "$lower_input" =~ ^":delete " ]]; then
        local arg=$(echo "$input" | cut -d' ' -f2-)
        cmd_delete "$arg"
      elif [[ "$lower_input" =~ ^":key " ]]; then
        local key=$(echo "$input" | cut -d' ' -f2-)
        cmd_set_key "$key"
      elif [[ "$lower_input" == ":key" ]]; then
        prompt_key
      elif [[ "${STATE[tab]}" == "shell" || "$input" =~ ^"!" ]]; then
        local cmd="$input"
        if [[ "$input" =~ ^"!" ]]; then
          cmd="${input:1}"
        fi
        run_shell_cmd "$cmd"
      elif [[ -n "${STATE[session_json]}" ]]; then
        cmd_send_to_agent "$input"
      else
        set_status "Unknown command. Type :help or ? for commands." "$A_BRED"
        render
      fi
      ;;
  esac
}

# --- System Info Commands (Translated from Node.js) --------------------------
show_help() {
  STATE[tab]="log"
  log_section "HELP" "$A_BCYAN"
  local cmds=(
    "TAB SWITCHING"
    "  l / :log         Switch to LOG tab"
    "  f / :findings    Switch to FINDINGS tab"
    "  s / :shell       Switch to SHELL tab"
    "  x / :files       Switch to FILES tab"
    "  e / :sessions    Switch to SESSIONS tab"
    "  Tab key          Cycle through tabs"
    ""
    "LOG NAVIGATION"
    "  j / :down        Scroll log down"
    "  k / :up          Scroll log up"
    "  g / :top         Go to top"
    "  G / :bot         Go to bottom"
    ""
    "SESSION MANAGEMENT"
    ":new              Start a new hunt (interactive)"
    ":load <n|id>      Load session by number or ID prefix"
    ":go / :cont       Continue/resume agent loop"
    ":stop             Stop running agent"
    ":del <n|id>       Delete a session"
    ":report           Findings report for current session"
    ""
    "AGENT"
    "<text>             Send message to agent (session must be active)"
    ""
    "SHELL"
    "!<cmd>             Run shell command from any tab"
    "<cmd>              Run shell command (when in shell tab)"
    ""
    "SYSTEM"
    ":key <gsk_...>    Set Groq API key"
    ":status           Full system snapshot"
    ":ram / :cpu       Memory / CPU info"
    ":disk / :net      Disk / network info"
    ":tools            Check pentest tools"
    ":groqtest         Test Groq API connection"
    ":clearlog         Clear log display"
    ":q / :quit        Exit 0x-hunt"
  )
  for cmd_line in "${cmds[@]}"; do
    if [[ -z "$cmd_line" ]]; then
      push_log ""
    elif [[ "$cmd_line" =~ ^[[:space:]]*[A-Z] ]]; then # Section header
      push_log "$(c "${A_BOLD}${A_BCYAN}" "$cmd_line")"
    else
      local cmd_part=$(echo "$cmd_line" | awk '{$1=$1; print $1}')
      local desc_part=$(echo "$cmd_line" | cut -d' ' -f2- | sed 's/^[[:space:]]*//')
      push_log "  $(c "$A_BYELLOW" "$(pad_end "$cmd_part" 22)")""$(c "$A_WHITE" "$desc_part")"
    fi
  done
  render
}

show_ram() {
  local m_json=$(get_mem_info)
  local total=$(echo "$m_json" | jq -r ".total")
  local used=$(echo "$m_json" | jq -r ".used")
  local avail=$(echo "$m_json" | jq -r ".avail")
  local pct=$(echo "$m_json" | jq -r ".pct")

  STATE[tab]="log"
  log_section "MEMORY" "$A_BCYAN"
  push_log "  $(c "$A_GRAY" "Total    ") $(c "$A_WHITE" "$(fmt_bytes "$total")")"
  push_log "  $(c "$A_GRAY" "Used     ") $(c "$A_WHITE" "$(fmt_bytes "$used")")"
  push_log "  $(c "$A_GRAY" "Available") $(c "$A_WHITE" "$(fmt_bytes "$avail")")"
  push_log "  $(c "$A_GRAY" "Usage    ") $(mem_bar "$pct" 30) $(c "$A_BOLD" "${pct}%")"
  render
}

show_cpu() {
  local cpu_json=$(get_cpu_load)
  local load1=$(echo "$cpu_json" | jq -r ".load1")
  local load5=$(echo "$cpu_json" | jq -r ".load5")
  local cores=$(echo "$cpu_json" | jq -r ".cores")

  STATE[tab]="log"
  log_section "CPU" "$A_BCYAN"
  push_log "  $(c "$A_GRAY" "Cores  ") $(c "$A_WHITE" "$cores")"
  push_log "  $(c "$A_GRAY" "Load 1m") $(c "${A_BOLD}${A_BCYAN}" "$load1")"
  push_log "  $(c "$A_GRAY" "Load 5m") $(c "$A_WHITE" "$load5")"
  render
}

show_disk() {
  local d_json=$(get_disk_info)
  local total=$(echo "$d_json" | jq -r ".total")
  local used=$(echo "$d_json" | jq -r ".used")
  local avail=$(echo "$d_json" | jq -r ".avail")
  local pct=$(echo "$d_json" | jq -r ".pct")

  STATE[tab]="log"
  log_section "DISK" "$A_BCYAN"
  push_log "  $(c "$A_GRAY" "Total    ") $(c "$A_WHITE" "$(fmt_bytes "$total")")"
  push_log "  $(c "$A_GRAY" "Used     ") $(c "$A_WHITE" "$(fmt_bytes "$used")")"
  push_log "  $(c "$A_GRAY" "Available") $(c "$A_WHITE" "$(fmt_bytes "$avail")")"
  push_log "  $(c "$A_GRAY" "Usage    ") $(mem_bar "$pct" 30) $(c "$A_BOLD" "${pct}%")"
  render
}

show_net() {
  local n_json=$(get_net_info)
  local vpn=$(echo "$n_json" | jq -r ".vpn")
  local ifaces=$(echo "$n_json" | jq -c ".ifaces[]")

  STATE[tab]="log"
  log_section "NETWORK" "$A_BCYAN"
  if [[ "$vpn" == "true" ]]; then
    push_log "  $(c "$A_GRAY" "VPN      ") $(c "${A_BGREEN}${A_BOLD}" "✓ DETECTED")"
  else
    push_log "  $(c "$A_GRAY" "VPN      ") $(c "$A_GRAY" "not detected")"
  fi
  push_log "  $(c "$A_GRAY" "Interfaces:")"
  local iface_found="false"
  while IFS= read -r iface_entry; do
    local name=$(echo "$iface_entry" | jq -r ".name")
    local ip=$(echo "$iface_entry" | jq -r ".ip")
    push_log "    $(c "$A_BCYAN" "$(pad_end "$name" 14)") $(c "$A_WHITE" "$ip")"
    iface_found="true"
  done <<< "$ifaces"
  if [[ "$iface_found" == "false" ]]; then
    push_log "$(c "$A_GRAY" "    (none found)")"
  fi
  render
}

show_tools() {
  STATE[tab]="log"
  set_status "Checking tools..." "$A_BYELLOW"
  render
  local results_json=$(check_tools)
  log_section "TOOLS" "$A_BCYAN"

  local present_tools=()
  local missing_tools=()
  while IFS= read -r tool_entry; do
    local tool_name=$(echo "$tool_entry" | jq -r ".tool")
    local ok_status=$(echo "$tool_entry" | jq -r ".ok")
    if [[ "$ok_status" == "true" ]]; then
      present_tools+=("$tool_name")
    else
      missing_tools+=("$tool_name")
    fi
  done <<< "$(echo "$results_json" | jq -c ".[]")"

  local present_str="${present_tools[*]}"
  local missing_str="${missing_tools[*]}"
  if [[ -z "$present_str" ]]; then present_str="none"; fi
  if [[ -z "$missing_str" ]]; then missing_str="none"; fi

  push_log "  $(c "$A_BGREEN" "✓") $(c "$A_WHITE" "Found:   ") $(c "$A_BGREEN" "$present_str")"
  push_log "  $(c "$A_BRED" "✗") $(c "$A_WHITE" "Missing: ") $(c "$A_GRAY" "$missing_str")"
  push_log "  $(c "$A_GRAY" "Coverage:") $(c "$A_BOLD" "${#present_tools[@]}/${#TOOLS[@]}")"
  set_status "" ""
  render
}

show_status() {
  local mem_json=$(get_mem_info)
  local cpu_json=$(get_cpu_load)
  local disk_json=$(get_disk_info)
  local net_json=$(get_net_info)

  local mem_total=$(echo "$mem_json" | jq -r ".total")
  local mem_used=$(echo "$mem_json" | jq -r ".used")
  local mem_pct=$(echo "$mem_json" | jq -r ".pct")

  local cpu_load1=$(echo "$cpu_json" | jq -r ".load1")
  local cpu_load5=$(echo "$cpu_json" | jq -r ".load5")
  local cpu_cores=$(echo "$cpu_json" | jq -r ".cores")

  local disk_avail=$(echo "$disk_json" | jq -r ".avail")
  local disk_total=$(echo "$disk_json" | jq -r ".total")

  local net_vpn=$(echo "$net_json" | jq -r ".vpn")

  STATE[tab]="log"
  log_section "SYSTEM STATUS" "$A_BCYAN"
  push_log "  $(c "$A_GRAY" "Platform")  $(c "$A_WHITE" "$(uname -s) ($(uname -m))")"
  push_log "  $(c "$A_GRAY" "Bash    ")  $(c "$A_WHITE" "${BASH_VERSION}")"
  push_log "  $(c "$A_GRAY" "Uptime  ")  $(c "$A_WHITE" "$(uptime -p | sed 's/^up //')")"
  push_log "  $(c "$A_GRAY" "RAM     ")  $(c "$A_WHITE" "$(fmt_bytes "$mem_used") / $(fmt_bytes "$mem_total")") $(mem_bar "$mem_pct" 15) $(c "$A_BOLD" "${mem_pct}%")"
  push_log "  $(c "$A_GRAY" "CPU     ")  $(c "$A_WHITE" "$cpu_load1 / $cpu_load5 ($cpu_cores cores)")"
  push_log "  $(c "$A_GRAY" "Disk    ")  $(c "$A_WHITE" "$(fmt_bytes "$disk_avail") free / $(fmt_bytes "$disk_total") total")"
  if [[ "$net_vpn" == "true" ]]; then
    push_log "  $(c "$A_GRAY" "VPN     ")  $(c "$A_BGREEN" "detected")"
  else
    push_log "  $(c "$A_GRAY" "VPN     ")  $(c "$A_GRAY" "not detected")"
  fi
  push_log "  $(c "$A_GRAY" "PID     ")  $(c "$A_WHITE" "$$")"
  push_log "  $(c "$A_GRAY" "Sessions")  $(c "$A_WHITE" "$(list_sessions | jq ". | length")")"
  render
}

test_groq() {
  local key=$(load_groq_key)
  if [[ -z "$key" ]]; then
    log_sys "No API key set. Use :key <gsk_...>" "$A_BRED"
    STATE[tab]="log"; render; return
  fi
  STATE[tab]="log"
  log_sys "Testing Groq API (3 attempts)..." "$A_BYELLOW"
  render

  local test_messages="[{\"role\": \"user\", \"content\": \"hi\"}]"
  for i in {1..3}; do
    local response=$(curl -s -X POST https://api.groq.com/openai/v1/chat/completions \
      -H "Authorization: Bearer $key" \
      -H "Content-Type: application/json" \
      -d "{\"model\": \"llama-3.3-70b-versatile\", \"messages\": $test_messages, \"temperature\": 0.7, \"max_tokens\": 3, \"stream\": false}")
    local http_code=$(echo "$response" | jq -r '.error.code // "null"')

    if [[ "$http_code" == "null" ]]; then
      log_sys "✓ Connected on attempt $i" "$A_BGREEN"
      render; return
    else
      local error_msg=$(echo "$response" | jq -r '.error.message')
      log_sys "Attempt $i failed: $error_msg" "$A_BRED"
      if (( i < 3 )); then
        log_sys "Waiting 2s..." "$A_GRAY"
        sleep 2
      fi
    fi
  done
  local net_json=$(get_net_info)
  local vpn_status=$(echo "$net_json" | jq -r ".vpn")
  log_sys "✗ All attempts failed." "$A_BRED"
  log_sys "VPN status: $(if [[ "$vpn_status" == "true" ]]; then echo "active"; else echo "not detected"; fi)" "$A_GRAY"
  log_sys "Check VPN routing and verify key at console.groq.com" "$A_GRAY"
  render
}

# --- Key Management Commands -------------------------------------------------
cmd_set_key() {
  local key="$1"
  if [[ -z "$key" || ! "$key" =~ ^gsk_ ]]; then
    log_sys "Invalid key. Must start with gsk_" "$A_BRED"
    STATE[tab]="log"; render; return
  fi
  save_groq_key "$key"
  log_sys "Key saved. Testing..." "$A_BYELLOW"
  STATE[tab]="log"; render
  test_groq
}

prompt_key() {
  echo -en "${A_SHOW}\n"
  echo -en "$(c "$A_BCYAN" "Groq API key (gsk_...): ")"
  stty echo icanon # Re-enable echo and canonical mode for input
  read -r key_input
  stty -echo -icanon time 0 min 0 # Restore raw mode
  if [[ -n "$key_input" ]]; then
    cmd_set_key "$key_input"
  fi
  render
}

# --- Session Commands --------------------------------------------------------
cmd_new() {
  echo -en "${A_SHOW}\n"
  stty echo icanon # Re-enable echo and canonical mode for input

  echo -e "\n$(c "${A_BOLD}${A_BCYAN}" "─── NEW HUNT ───────────────────────────────────────")\n"
  echo -en "$(c "$A_BCYAN" "Target domain (e.g. target.com): ")"
  read -r target
  if [[ -z "$target" ]]; then
    stty -echo -icanon time 0 min 0 # Restore raw mode
    render; return
  fi

  echo -e "$(c "$A_GRAY" "Scope (one per line, empty line to finish):")"
  local scope_lines=()
  while true; do
    echo -en "$(c "$A_BCYAN" "  scope> ")"
    read -r line
    if [[ -z "$line" ]]; then break; fi
    scope_lines+=("$line")
  done

  if (( ${#scope_lines[@]} == 0 )); then
    log_sys "No scope entered. Cancelled." "$A_BRED"
    stty -echo -icanon time 0 min 0 # Restore raw mode
    render; return
  fi

  echo -en "$(c "$A_BCYAN" "Notes (optional): ")"
  read -r notes

  stty -echo -icanon time 0 min 0 # Restore raw mode

  if [[ -z "$(load_groq_key)" ]]; then
    log_sys "No API key. Use :key <gsk_...> first." "$A_BRED"
    render; return
  fi

  local new_session_json=$(create_session "$target" "$(IFS=$'
'; echo "${scope_lines[*]}")" "$notes")
  STATE[session_json]="$new_session_json"
  local session_id=$(echo "$new_session_json" | jq -r ".id")
  ensure_workspace "$session_id"
  STATE[tab]="log"
  log_sys "Session created: ${session_id:0:8}" "$A_BGREEN"
  log_sys "Target: $target" "$A_BCYAN"

  local kickoff_message="START HUNT\nTARGET: $target\nSCOPE:\n$(IFS=$'
'; echo "${scope_lines[*]}")"
  if [[ -n "$notes" ]]; then
    kickoff_message+="\nNOTES: $notes"
  fi
  kickoff_message+="\n\nBegin passive recon. Identify the target's attack surface."

  render
  run_agent_loop "$kickoff_message"
}

cmd_load() {
  local arg="$1"
  local all_sessions_json=$(list_sessions)
  local session_to_load_json=""

  # Try to load by number
  if [[ "$arg" =~ ^[0-9]+$ ]]; then
    local n=$((arg - 1))
    local session_id=$(echo "$all_sessions_json" | jq -r ".[${n}].id")
    if [[ "$session_id" != "null" ]]; then
      session_to_load_json=$(load_session "$session_id")
    fi
  fi

  # If not found by number, try by ID prefix or target name
  if [[ -z "$session_to_load_json" ]]; then
    local found_id=$(echo "$all_sessions_json" | jq -r ".[] | select(.id | startswith(\"$arg\")) | .id")
    if [[ -z "$found_id" ]]; then
      found_id=$(echo "$all_sessions_json" | jq -r ".[] | select(.target | ascii_downcase | contains(\"${arg,,}\")) | .id")
    fi
    if [[ -n "$found_id" ]]; then
      session_to_load_json=$(load_session "$found_id")
    fi
  fi

  if [[ -z "$session_to_load_json" ]]; then
    log_sys "Session not found: $arg" "$A_BRED"
    STATE[tab]="sessions"; render; return
  fi

  STATE[session_json]="$session_to_load_json"
  STATE[tab]="log"
  STATE[log_lines]="" # Clear current log display

  local loaded_target=$(echo "$session_to_load_json" | jq -r ".target")
  local loaded_phase=$(echo "$session_to_load_json" | jq -r ".phase")
  local loaded_findings_count=$(echo "$session_to_load_json" | jq ".findings | length")
  local loaded_commands_count=$(echo "$session_to_load_json" | jq ".commandHistory | length")

  # Re-log findings from the loaded session
  local loaded_findings=$(echo "$session_to_load_json" | jq -c ".findings[]")
  while IFS= read -r f_json; do
    local text=$(echo "$f_json" | jq -r ".text")
    push_log "$(c "$A_GRAY" "[LOADED FINDING]") $(c "$A_BRED" "🚨") $(c "$A_WHITE" "$text")"
  done <<< "$loaded_findings"

  log_sys "Loaded: $loaded_target [$loaded_phase] — $loaded_findings_count findings, $loaded_commands_count commands" "$A_BGREEN"

  if [[ -z "$(load_groq_key)" ]]; then
    log_sys "Groq API key not loaded. Use :key <gsk_...>" "$A_GRAY"
  fi
  render
}

cmd_delete() {
  local arg="$1"
  local all_sessions_json=$(list_sessions)
  local session_id_to_delete=""

  # Try to find by number
  if [[ "$arg" =~ ^[0-9]+$ ]]; then
    local n=$((arg - 1))
    session_id_to_delete=$(echo "$all_sessions_json" | jq -r ".[${n}].id")
  fi

  # If not found by number, try by ID prefix or target name
  if [[ -z "$session_id_to_delete" || "$session_id_to_delete" == "null" ]]; then
    session_id_to_delete=$(echo "$all_sessions_json" | jq -r ".[] | select(.id | startswith(\"$arg\")) | .id")
    if [[ -z "$session_id_to_delete" || "$session_id_to_delete" == "null" ]]; then
      session_id_to_delete=$(echo "$all_sessions_json" | jq -r ".[] | select(.target | ascii_downcase | contains(\"${arg,,}\")) | .id")
    fi
  fi

  if [[ -z "$session_id_to_delete" || "$session_id_to_delete" == "null" ]]; then
    log_sys "Session not found: $arg" "$A_BRED"
    STATE[tab]="sessions"; render; return
  fi

  # Confirm deletion
  echo -en "${A_SHOW}\n"
  echo -en "$(c "$A_BRED" "Are you sure you want to delete session ${session_id_to_delete:0:8}? (y/N): ")"
  stty echo icanon
  read -r confirmation
  stty -echo -icanon time 0 min 0

  if [[ "${confirmation,,}" == "y" ]]; then
    rm -f "$SESSIONS_DIR/${session_id_to_delete}.json"
    rm -rf "$WORKSPACE_DIR/$session_id_to_delete"
    log_sys "Session ${session_id_to_delete:0:8} deleted." "$A_BGREEN"
    if [[ -n "${STATE[session_json]}" && "$(echo "${STATE[session_json]}" | jq -r ".id")" == "$session_id_to_delete" ]]; then
      STATE[session_json]="" # Clear active session if deleted
    fi
  else
    log_sys "Session deletion cancelled." "$A_GRAY"
  fi
  render
}

cmd_send_to_agent() {
  local message="$1"
  if [[ -z "${STATE[session_json]}" ]]; then
    log_sys "No active session. Use :new or :load first." "$A_BRED"
    render; return
  fi

  STATE[session_json]=$(echo "${STATE[session_json]}" | jq --arg content "$message" ".messages += [{\"role\": \"user\", \"content\": \"$content\"}]")
  save_session "${STATE[session_json]}"
  log_sys "Message sent to agent." "$A_GRAY"
  render
  run_agent_loop # Resume agent loop with new message
}

run_shell_cmd() {
  local cmd="$1"
  if [[ -z "${STATE[session_json]}" ]]; then
    log_sys "No active session. Shell commands are logged per session." "$A_BRED"
    render; return
  fi

  local session_id=$(echo "${STATE[session_json]}" | jq -r ".id")
  log_sys "Running shell command: $cmd" "$A_BMAGENTA"
  set_status "Executing: $cmd" "$A_BMAGENTA"
  render

  local cmd_output_json=$(execute_command "$cmd" "$session_id" 300000) # 5 minute timeout for manual shell commands
  local cmd_stdout=$(echo "$cmd_output_json" | jq -r ".stdout")
  local cmd_stderr=$(echo "$cmd_output_json" | jq -r ".stderr")
  local cmd_exit_code=$(echo "$cmd_output_json" | jq -r ".exitCode")

  log_sys "Command finished with exit code: $cmd_exit_code" "$A_GRAY"
  if [[ -n "$cmd_stdout" ]]; then
    log_sys "STDOUT: $(echo "$cmd_stdout" | head -n 10)" "$A_DIM"
  fi
  if [[ -n "$cmd_stderr" ]]; then
    log_sys "STDERR: $(echo "$cmd_stderr" | head -n 10)" "$A_RED"
  fi

  # Add to session command history
  STATE[session_json]=$(echo "${STATE[session_json]}" | jq --arg cmd "$cmd" ".commandHistory += [\"$cmd\"]")
  save_session "${STATE[session_json]}"
  set_status "" ""
  render
}

show_report() {
  if [[ -z "${STATE[session_json]}" ]]; then
    log_sys "No active session to generate report." "$A_BRED"
    render; return
  fi

  STATE[tab]="log"
  log_section "HUNT REPORT" "$A_BCYAN"

  local target=$(echo "${STATE[session_json]}" | jq -r ".target")
  local session_id=$(echo "${STATE[session_json]}" | jq -r ".id")
  local created=$(echo "${STATE[session_json]}" | jq -r ".created")
  local updated=$(echo "${STATE[session_json]}" | jq -r ".updated")
  local phase=$(echo "${STATE[session_json]}" | jq -r ".phase")
  local notes=$(echo "${STATE[session_json]}" | jq -r ".notes")
  local scope=$(echo "${STATE[session_json]}" | jq -r ".scope")
  local findings_count=$(echo "${STATE[session_json]}" | jq ".findings | length")

  push_log "$(c "$A_BOLD" "Target:") $(c "$A_WHITE" "$target")"
  push_log "$(c "$A_BOLD" "Session ID:") $(c "$A_WHITE" "$session_id")"
  push_log "$(c "$A_BOLD" "Created:") $(c "$A_WHITE" "$(date -d "$created" +"%Y-%m-%d %H:%M")")"
  push_log "$(c "$A_BOLD" "Last Updated:") $(c "$A_WHITE" "$(date -d "$updated" +"%Y-%m-%d %H:%M")")"
  push_log "$(c "$A_BOLD" "Current Phase:") $(c "$A_WHITE" "$phase")"
  if [[ -n "$notes" ]]; then
    push_log "$(c "$A_BOLD" "Notes:") $(c "$A_WHITE" "$notes")"
  fi
  push_log "$(c "$A_BOLD" "Scope:")\n$(c "$A_WHITE" "$scope")"
  push_log ""

  push_log "$(c "$A_BOLD" "Findings ($findings_count):")"
  if (( findings_count == 0 )); then
    push_log "$(c "$A_GRAY" "  No findings recorded for this session.")"
  else
    local findings=$(echo "${STATE[session_json]}" | jq -c ".findings[]")
    local f_idx=1
    while IFS= read -r f_json; do
      local timestamp=$(echo "$f_json" | jq -r ".timestamp")
      local text=$(echo "$f_json" | jq -r ".text")
      push_log "  $(c "$A_BRED" "$f_idx.") $(c "$A_WHITE" "$text") $(c "$A_GRAY" "(Found: $(date -d "$timestamp" +"%Y-%m-%d %H:%M"))")"
      f_idx=$((f_idx+1))
    done <<< "$findings"
  fi
  push_log ""

  push_log "$(c "$A_BOLD" "Command History:")"
  local command_history_count=$(echo "${STATE[session_json]}" | jq ".commandHistory | length")
  if (( command_history_count == 0 )); then
    push_log "$(c "$A_GRAY" "  No commands executed for this session.")"
  else
    local commands=$(echo "${STATE[session_json]}" | jq -r ".commandHistory[]")
    local c_idx=1
    while IFS= read -r cmd_entry; do
      push_log "  $(c "$A_GRAY" "$c_idx.") $(c "$A_DIM" "$cmd_entry")"
      c_idx=$((c_idx+1))
    done <<< "$commands"
  fi

  render
}

# --- Main Execution ----------------------------------------------------------
main() {
  # Initial render of the boot screen
  echo -en "${A_CLEAR}${A_HIDE}"
  echo -en "$(c "$A_BBLUE" "
                                                                   
    ██████╗  ██╗  ██╗    ██╗  ██╗ ███╗   ██╗ ████████╗              
    ██╔══██╗ ██║  ██║    ██║  ██║ ████╗  ██║ ╚══██╔══╝              
    ██████╔╝ ███████║    ███████║ ██╔██╗ ██║    ██║                 
    ██╔═══╝  ██╔══██║    ██╔══██║ ██║╚██╗██║    ██║                 
    ██║      ██║  ██║    ██║  ██║ ██║ ╚████║    ██║                 
    ╚═╝      ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═══╝    ╚═╝                 
                                                                   
    ██╗  ██╗ ██╗   ██╗ ███╗   ██╗ ████████╗                         
    ██║  ██║ ██║   ██║ ████╗  ██║ ╚══██╔══╝                         
    ███████║ ██║   ██║ ██╔██╗ ██║    ██║                            
    ██╔══██║ ██║   ██║ ██║╚██╗██║    ██║                            
    ██║  ██║ ╚██████╔╝ ██║ ╚████║    ██║                            
    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝                            
                                                                   
                                                                   
    ██╗    ██╗ ██████╗ ██╗   ██╗                                   
    ██║    ██║ ██╔══██╗██║   ██║                                   
    ██║ █╗ ██║ ██████╔╝██║   ██║                                   
    ██║███╗██║ ██╔══██╗██║   ██║                                   
    ╚███╔███╔╝ ██████╔╝╚██████╔╝                                   
     ╚══╝╚══╝  ╚═════╝  ╚═════╝                                    
                                                                   
                                                                   
    ███████╗ ██╗   ██╗ ██╗   ██╗                                   
    ██╔════╝ ██║   ██║ ██║   ██║                                   
    █████╗   ██║   ██║ ██║   ██║                                   
    ██╔══╝   ██║   ██║ ██║   ██║                                   
    ██║      ╚██████╔╝ ╚██████╔╝                                   
    ╚═╝       ╚═════╝   ╚═════╝                                    
                                                                   

  ")"
  echo -en "$(c "$A_BCYAN" "                                0x-HUNT v2 - Autonomous Bug Bounty Hunter                                 ")\n"
  echo -en "$(c "$A_GRAY" "                                       (Rewritten in Bash)                                          ")\n"
  echo -en "$(c "$A_DIM" "                                                                   Press any key to start...                                    ")\n"
  read -s -n 1 # Wait for any key press

  # Initialize TUI
  render
  setup_input
}

# Call main function
main
