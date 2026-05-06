#!/bin/bash
# ============================================================================
# Linux Security Audit Script - Gagaltotal666
# Version: 3.3
# Supported: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, SUSE, Alpine, K8s, CI/CD
# ============================================================================

set -o pipefail

# ==================== GLOBAL VARIABLES ====================
readonly SCRIPT_VERSION="3.3"
readonly TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
readonly HOSTNAME_VAR=$(hostname 2>/dev/null || echo "unknown")
readonly OUTPUT_DIR="LinuxAudit-${HOSTNAME_VAR}-${TIMESTAMP}"
readonly OUTPUT_FILE="${OUTPUT_DIR}/LinuxAudit.txt"
readonly TEMP_OUTPUT="/tmp/linux_audit_temp_${TIMESTAMP}.txt"
readonly LOG_FILE="${OUTPUT_DIR}/audit_errors.log"
readonly THREAT_LOG="${OUTPUT_DIR}/threats_detected.log"
DISTRO_FAMILY=""
THREAT_COUNT=0

declare -A CONSOLE_THREAT_CACHE

# ==================== COLOR DEFINITIONS ====================
if [[ -t 1 ]] && command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'; BOLD='\033[1m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' NC='' BOLD=''
fi

# ==================== TRAP HANDLERS ====================
trap 'cleanup' EXIT
trap 'ctrl_c' INT TERM

cleanup() {
    local exit_code=$?
    rm -f "$TEMP_OUTPUT" 2>/dev/null
    if [[ -f "$LOG_FILE" ]] && [[ -s "$LOG_FILE" ]]; then
        echo -e "\n${YELLOW}[!] Error log tersimpan di: $LOG_FILE${NC}" >&2
    else
        rm -f "$LOG_FILE" 2>/dev/null
    fi
    exit $exit_code
}

ctrl_c() {
    echo -e "\n${RED}** Anda menekan Ctrl+C... Keluar${NC}" >&2
    rm -f "$TEMP_OUTPUT" 2>/dev/null
    exit 130
}

# ==================== THREAT LOGGING SYSTEM ====================
log_threat() {
    local severity="$1"
    local category="$2"
    local details="$3"
    local file_path="$4"
    
    local unique_id="$category|$details|$file_path"
    
    if [[ -n "${CONSOLE_THREAT_CACHE[$unique_id]}" ]]; then
        return 0 
    fi
    CONSOLE_THREAT_CACHE["$unique_id"]=1
    
    ((THREAT_COUNT++))
    
    local log_line="[$(date '+%Y-%m-%d %H:%M:%S')] [$severity] [$category] $details"
    [[ -n "$file_path" ]] && log_line="$log_line | PATH: $file_path"
    
    if ! grep -qF "$category|$details|$file_path" "$THREAT_LOG" 2>/dev/null; then
        echo "$log_line" >> "$THREAT_LOG"
    fi
    
    case "$severity" in
        CRITICAL) echo -e "${RED}[!!!] CRITICAL: $details${NC}" ;;
        HIGH)     echo -e "${RED}[!!] HIGH: $details${NC}" ;;
        MEDIUM)   echo -e "${YELLOW}[!] MEDIUM: $details${NC}" ;;
    esac
    
    if [[ -n "$file_path" ]]; then
        echo -e "${RED}           -> $file_path${NC}"
    fi
}

# ==================== UTILITY FUNCTIONS ====================
log_error() {
    echo "[ERROR][$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true
}

is_ignored_error() {
    local error_msg="$1"
    [[ "$error_msg" =~ ^du:.*cannot\ access.*\/proc ]] && return 0
    [[ "$error_msg" =~ ^du:.*cannot\ read.*\/proc ]] && return 0
    [[ "$error_msg" =~ ^find:.*\/proc ]] && return 0
    [[ "$error_msg" =~ ^find:.*\/sys ]] && return 0
    [[ "$error_msg" =~ Permission\ denied ]] && return 0
    [[ "$error_msg" =~ Operation\ not\ permitted ]] && return 0
    [[ "$error_msg" =~ broken\ pipe ]] && return 0
    return 1
}

safe_exec() {
    if [[ $# -eq 0 ]]; then log_error "safe_exec tanpa argumen"; return 1; fi
    local cmd="$1"; shift
    if ! command -v "$cmd" &>/dev/null; then log_error "Perintah tidak ditemukan: $cmd"; return 127; fi
    
    local stderr_file
    stderr_file=$(mktemp 2>/dev/null || echo "/tmp/safe_exec_err_$$")
    "$cmd" "$@" 2>"$stderr_file"
    local status=$?
    
    if [[ $status -ne 0 ]] && [[ $status -ne 141 ]]; then
        while IFS= read -r line; do
            is_ignored_error "$line" || log_error "[$cmd] $line"
        done < "$stderr_file"
    fi
    rm -f "$stderr_file" 2>/dev/null
    return $status
}

safe_find() {
    local start_dir="${1:-/}"; shift
    if ! command -v find &>/dev/null; then log_error "find tidak tersedia"; return 127; fi
    local exclude_args=(! -path "/proc/*" ! -path "/sys/*")
    timeout 30 find "$start_dir" "${exclude_args[@]}" "$@" 2>/dev/null
    [[ $? -eq 124 ]] && echo "[TIMEOUT] Pencarian dibatalkan setelah 30 detik"
    return 0
}

print_header() {
    local title="$1"
    local line="═══════════════════════════════════════════════════════════════════════════════"
    printf "\n${CYAN}%s${NC}\n" "$line"
    printf "${BOLD}[+] %s${NC}\n" "$title"
    printf "${CYAN}%s${NC}\n" "$line"
}

print_sub() { printf "\n${GREEN}[+] %s${NC}\n" "$1"; }

# ==================== DISTRO DETECTION ====================
detect_distro() {
    local distro="" version="" family="" id=""
    if [[ -f /etc/os-release ]]; then
        while IFS='=' read -r key value; do
            value="${value#\"}"; value="${value%\"}"
            case "$key" in NAME) distro="$value" ;; VERSION) version="$value" ;; ID) id="$value" ;; esac
        done < /etc/os-release
        case "$id" in
            ubuntu|debian|linuxmint|pop|kali|parrot|mx) family="debian" ;;
            centos|rhel|fedora|rocky|almalinux|ol|oraclelinux|scientific) family="rhel" ;;
            arch|manjaro|endeavouros|garuda|cachyos) family="arch" ;;
            opensuse-leap|opensuse-tumbleweed|sles|sle-hpc) family="suse" ;;
            alpine) family="alpine" ;; gentoo|funtoo) family="gentoo" ;;
            void) family="void" ;; slackware) family="slackware" ;; *) family="other" ;;
        esac
    elif [[ -f /etc/redhat-release ]]; then distro=$(cat /etc/redhat-release 2>/dev/null); family="rhel"
    elif [[ -f /etc/SuSE-release ]]; then distro=$(cat /etc/SuSE-release 2>/dev/null | head -1); family="suse"
    elif [[ -f /etc/arch-release ]]; then distro="Arch Linux"; family="arch"
    elif [[ -f /etc/alpine-release ]]; then distro="Alpine Linux $(cat /etc/alpine-release 2>/dev/null)"; family="alpine"
    elif [[ -f /etc/gentoo-release ]]; then distro=$(cat /etc/gentoo-release 2>/dev/null); family="gentoo"
    elif [[ -f /etc/slackware-version ]]; then distro="Slackware $(cat /etc/slackware-version 2>/dev/null)"; family="slackware"
    else distro="Unknown Distribution"; family="unknown"
    fi
    distro="${distro:-Unknown}"; version="${version:-Unknown}"; family="${family:-unknown}"
    DISTRO_FAMILY="$family"
    echo "${distro}|${version}|${family}"
}

get_webserver_log_path() {
    local server="$1"; local family="${DISTRO_FAMILY:-debian}"
    case "$server" in
        apache|httpd) case "$family" in debian|alpine) echo "/var/log/apache2" ;; *) echo "/var/log/httpd" ;; esac ;;
        nginx) echo "/var/log/nginx" ;; *) echo "" ;;
    esac
}

get_webserver_service_name() {
    local server="$1"; local family="${DISTRO_FAMILY:-debian}"
    case "$server" in
        apache|httpd) case "$family" in debian|alpine) echo "apache2" ;; *) echo "httpd" ;; esac ;;
        nginx) echo "nginx" ;; *) echo "" ;;
    esac
}

get_package_manager() {
    case "${DISTRO_FAMILY:-unknown}" in
        debian) echo "apt" ;; rhel) echo "yum" ;; arch) echo "pacman" ;;
        suse) echo "zypper" ;; alpine) echo "apk" ;; fedora) echo "dnf" ;; *) echo "unknown" ;;
    esac
}

get_auth_log_path() {
    case "${DISTRO_FAMILY:-unknown}" in debian) echo "/var/log/auth.log" ;; *) echo "/var/log/secure" ;; esac
}

# ==================== ORIGINAL AUDIT FUNCTIONS ====================
audit_system_information() {
    print_header "LINUX SYSTEM INFORMATION"
    print_sub "Linux Kernel Information"; safe_exec uname -a
    print_sub "Linux Distribution Information"
    local distro_info=$(detect_distro)
    echo "Distro       : $(echo "$distro_info" | cut -d'|' -f1)"; echo "Version      : $(echo "$distro_info" | cut -d'|' -f2)"
    echo "Family       : $(echo "$distro_info" | cut -d'|' -f3)"; echo "Architecture : $(uname -m 2>/dev/null || echo 'unknown')"
    print_sub "Uptime Information"; safe_exec uptime
    print_sub "CPU Information"
    if command -v lscpu &>/dev/null; then lscpu 2>/dev/null | grep -E "^(Architecture|CPU\(s\)|Model name|Thread|Core|Socket|CPU MHz|Cache size|Virtualization)" || true
    else grep -E "^(model name|processor|cpu cores|cpu MHz)" /proc/cpuinfo 2>/dev/null | head -20; fi
    print_sub "Disk Space Usage"; if command -v df &>/dev/null; then df -hT 2>/dev/null || df -h 2>/dev/null; fi
    print_sub "Disk Usage by Directory (Top 15)"
    if du --help 2>/dev/null | grep -q '\-\-exclude'; then
        du -h --max-depth=1 --exclude='/proc' --exclude='/sys' --exclude='/dev' --exclude='/run' --exclude='/tmp' --exclude='/snap' / 2>/dev/null | sort -rh | head -15
    else
        local -a scan_dirs=("/home" "/var" "/usr" "/opt" "/root" "/srv")
        for dir in "${scan_dirs[@]}"; do [[ -d "$dir" ]] && du -h --max-depth=1 "$dir" 2>/dev/null || true; done | sort -rh | head -15
    fi
    print_sub "Memory Information"; if command -v free &>/dev/null; then free -h 2>/dev/null; else head -15 /proc/meminfo 2>/dev/null; fi
    print_sub "Swap Information"; if command -v swapon &>/dev/null; then swapon --show 2>/dev/null || cat /proc/swaps 2>/dev/null; elif [[ -f /proc/swaps ]]; then cat /proc/swaps; fi
    print_sub "TCP Wrappers Configuration"
    echo "--- /etc/hosts.allow ---"; [[ -f /etc/hosts.allow ]] && cat /etc/hosts.allow 2>/dev/null || echo "(not found)"
    echo ""; echo "--- /etc/hosts.deny ---"; [[ -f /etc/hosts.deny ]] && cat /etc/hosts.deny 2>/dev/null || echo "(not found)"
    print_sub "Cron Jobs"
    echo "--- User Crontabs ---"
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
            local crontab_content=$(crontab -l -u "$username" 2>/dev/null) && { echo "[$username ($uid)]:"; echo "$crontab_content"; echo ""; }
        fi
    done < /etc/passwd
    echo "--- System Crontab ---"; [[ -f /etc/crontab ]] && cat /etc/crontab 2>/dev/null
    echo ""; echo "--- Cron Directories ---"
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$cron_dir" ]] && { echo ""; echo "=== $cron_dir ==="; ls -la "$cron_dir" 2>/dev/null; }
    done
    print_sub "Systemd Timers"; if command -v systemctl &>/dev/null; then systemctl list-timers --all --no-pager 2>/dev/null | head -30; fi
    print_sub "Last Reboots"; if command -v last &>/dev/null; then last reboot 2>/dev/null | head -15; elif command -v journalctl &>/dev/null; then journalctl --list-boots --no-pager 2>/dev/null | head -15; fi
    print_sub "System Load Average"; [[ -f /proc/loadavg ]] && cat /proc/loadavg
    print_sub "Environment Variables (Security Relevant)"; env 2>/dev/null | grep -iE "^(PATH|LD_PRELOAD|PYTHONPATH|PERL5LIB|CLASSPATH|LD_LIBRARY_PATH|PROMPT_COMMAND|BASH_FUNC)=" || echo "(none found)"
}

audit_users_and_groups() {
    print_header "USERS AND GROUPS CHECKS"
    print_sub "Current User Information"
    echo "User   : $(whoami 2>/dev/null || echo 'unknown')"; echo "ID     : $(id 2>/dev/null || echo 'unknown')"; echo "Groups : $(groups 2>/dev/null || echo 'unknown')"
    print_sub "Currently Logged In Users"; safe_exec w
    print_sub "Login History (Last 20)"; if command -v last &>/dev/null; then last -20 2>/dev/null; fi
    print_sub "Failed Login Attempts"
    local auth_log=$(get_auth_log_path)
    if command -v journalctl &>/dev/null && [[ -d /var/log/journal ]]; then
        journalctl -u sshd --since "7 days ago" --no-pager 2>/dev/null | grep -iE "failed|invalid" | tail -50 || true
    elif [[ -f "$auth_log" ]]; then grep -iE "failed|invalid" "$auth_log" 2>/dev/null | tail -50 || true
    elif [[ -f /var/log/messages ]]; then grep -iE "failed|invalid" /var/log/messages 2>/dev/null | tail -30 || true
    else echo "(auth log not found)"; fi
    print_sub "All Users with Login Shells"
    printf "%-20s %-8s %-15s %-30s\n" "USERNAME" "UID" "GID" "SHELL"; printf "%-20s %-8s %-15s %-30s\n" "--------" "---" "---" "-----"
    while IFS=: read -r username _ uid gid _ home shell; do
        case "$shell" in */nologin|*/false|*/sync|*/halt|*/shutdown) continue ;; esac
        printf "%-20s %-8s %-15s %-30s\n" "$username" "$uid" "$gid" "$shell"
    done < /etc/passwd
    print_sub "Users with UID 0 (Root Equivalent)"
    local uid0_users=$(awk -F: '($3 == 0){print $1}' /etc/passwd 2>/dev/null)
    if [[ -n "$uid0_users" ]]; then
        echo "$uid0_users" | while read -r user; do
            if [[ "$user" != "root" ]]; then log_threat "CRITICAL" "UID0_BACKDOOR" "User '$user' memiliki UID 0 (Root Equivalent)!" "/etc/passwd"
            else echo "root (expected)"; fi
        done
    fi
    print_sub "Empty Password Check"
    if [[ -r /etc/shadow ]]; then
        local empty_pass=$(awk -F: '($2 == "" || $2 == "!"){print $1}' /etc/shadow 2>/dev/null)
        if [[ -n "$empty_pass" ]]; then echo "WARNING: Users with empty or disabled passwords:"; echo "$empty_pass"
        else echo "(no empty passwords found)"; fi
    else echo "Cannot read /etc/shadow (root required)"; fi
    print_sub "Password Policy (/etc/login.defs)"; if [[ -f /etc/login.defs ]]; then grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD)" /etc/login.defs 2>/dev/null || echo "(no policy found)"; else echo "(file not found)"; fi
    print_sub "Groups with Members"; echo "--- /etc/group entries with members ---"; while IFS=: read -r group _ gid members; do [[ -n "$members" ]] && echo "$group ($gid): $members"; done < /etc/group
    print_sub "Sudoers Configuration"
    if [[ -d /etc/sudoers.d ]]; then echo "--- /etc/sudoers.d/ contents ---"; ls -la /etc/sudoers.d/ 2>/dev/null; echo ""; for sudofile in /etc/sudoers.d/*; do [[ -f "$sudofile" ]] && { echo "=== $sudofile ==="; grep -vE '^#|^$' "$sudofile" 2>/dev/null || true; echo ""; }; done; fi
    echo "--- /etc/sudoers (active lines) ---"; if [[ -r /etc/sudoers ]]; then grep -vE '^#|^$|^Defaults' /etc/sudoers 2>/dev/null || echo "(empty)"; else echo "Cannot read /etc/sudoers"; fi
    print_sub "PAM Configuration"
    for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -f "$pam_file" ]] && { echo "=== $pam_file ==="; grep -vE '^#|^$' "$pam_file" 2>/dev/null || true; echo ""; }
    done
    print_sub "Processes Running as Root"; ps -U root -u root u 2>/dev/null | head -40
}

audit_networking() {
    print_header "NETWORKING CHECKS"
    print_sub "Active Internet Connections (TCP)"
    if command -v ss &>/dev/null; then echo "--- Listening TCP Ports ---"; ss -tlnp 2>/dev/null; echo ""; echo "--- Established TCP Connections ---"; ss -tnp state established 2>/dev/null
    elif command -v netstat &>/dev/null; then netstat -tlnp 2>/dev/null; echo ""; netstat -tnp 2>/dev/null | grep ESTABLISHED; else head -20 /proc/net/tcp 2>/dev/null; fi
    print_sub "Active Internet Connections (UDP)"; if command -v ss &>/dev/null; then ss -ulnp 2>/dev/null; elif command -v netstat &>/dev/null; then netstat -ulnp 2>/dev/null; fi
    print_sub "Network Interfaces"; if command -v ip &>/dev/null; then ip addr show 2>/dev/null; elif command -v ifconfig &>/dev/null; then ifconfig -a 2>/dev/null; else cat /proc/net/dev 2>/dev/null; fi
    print_sub "IP Routing Table"; if command -v ip &>/dev/null; then ip route show 2>/dev/null; elif command -v route &>/dev/null; then route -n 2>/dev/null; fi
    print_sub "DNS Configuration"; echo "--- /etc/resolv.conf ---"; [[ -f /etc/resolv.conf ]] && cat /etc/resolv.conf 2>/dev/null; echo ""; echo "--- /etc/hosts ---"; [[ -f /etc/hosts ]] && cat /etc/hosts 2>/dev/null
    print_sub "ARP Table"; if command -v ip &>/dev/null; then ip neigh show 2>/dev/null; elif command -v arp &>/dev/null; then arp -an 2>/dev/null; fi
    print_sub "Connection Summary"
    if command -v ss &>/dev/null; then
        echo "TCP Listening : $(ss -tlnp 2>/dev/null | grep -c LISTEN || echo 0)"; echo "UDP Listening : $(ss -ulnp 2>/dev/null | wc -l || echo 0)"
        echo "Established   : $(ss -tnp state established 2>/dev/null | wc -l || echo 0)"; ss -s 2>/dev/null
    fi
    print_sub "Firewall Status"
    if command -v ufw &>/dev/null; then echo "--- UFW ---"; ufw status verbose 2>/dev/null || echo "(cannot get status)"; fi
    if command -v firewall-cmd &>/dev/null; then echo "--- Firewalld ---"; echo "State: $(firewall-cmd --state 2>/dev/null || echo 'unknown')"; firewall-cmd --list-all 2>/dev/null || true; fi
    if command -v iptables &>/dev/null; then echo "--- iptables (filter table) ---"; iptables -L -n -v --line-numbers 2>/dev/null | head -60; fi
    if command -v nft &>/dev/null; then echo "--- nftables ---"; nft list ruleset 2>/dev/null | head -60; fi
    if command -v csf &>/dev/null; then echo "--- CSF Firewall ---"; csf -s 2>/dev/null || true; fi
}

audit_services() {
    print_header "SERVICES CHECKS"
    print_sub "Systemd Running Services"; if command -v systemctl &>/dev/null; then systemctl list-units --type=service --state=running --no-pager 2>/dev/null; fi
    print_sub "Services Enabled at Boot"; if command -v systemctl &>/dev/null; then systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null; fi
    print_sub "Failed Services"; if command -v systemctl &>/dev/null; then systemctl --failed --no-pager 2>/dev/null; fi
    print_sub "Legacy SysV Services (if applicable)"; if [[ -x /sbin/service ]] || [[ -x /usr/sbin/service ]]; then service --status-all 2>/dev/null | grep '\[ + \]' || echo "(no SysV services running)"; fi
    print_sub "Process Tree"; if command -v pstree &>/dev/null; then pstree -paul 2>/dev/null | head -100; else ps -ef --forest 2>/dev/null | head -100; fi
    print_sub "Top CPU Consuming Processes"; ps aux --sort=-%cpu 2>/dev/null | head -15
    print_sub "Top Memory Consuming Processes"; ps aux --sort=-%mem 2>/dev/null | head -15
    print_sub "Socket Statistics"; if command -v ss &>/dev/null; then ss -s 2>/dev/null; fi
}

audit_security() {
    print_header "SECURITY CHECKS"
    print_sub "SSH Server Configuration"
    local ssh_configs="/etc/ssh/sshd_config"; [[ -d /etc/ssh/sshd_config.d ]] && ssh_configs="$ssh_configs /etc/ssh/sshd_config.d/*.conf"
    for ssh_conf in $ssh_configs; do [[ -f "$ssh_conf" ]] && { echo "=== $ssh_conf ==="; grep -vE '^#|^$' "$ssh_conf" 2>/dev/null || true; echo ""; }; done
    print_sub "SSH Security Assessment"
    if [[ -f /etc/ssh/sshd_config ]]; then
        local sshd_conf="/etc/ssh/sshd_config"
        if [[ -d /etc/ssh/sshd_config.d ]]; then for f in /etc/ssh/sshd_config.d/*.conf; do [[ -f "$f" ]] && sshd_conf="$sshd_conf $f"; done; fi
        echo "PermitRootLogin         : $(grep -ih "^PermitRootLogin" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set")"
        echo "PasswordAuthentication  : $(grep -ih "^PasswordAuthentication" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set")"
        echo "PermitEmptyPasswords    : $(grep -ih "^PermitEmptyPasswords" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set")"
        echo "X11Forwarding           : $(grep -ih "^X11Forwarding" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set")"
        echo "MaxAuthTries            : $(grep -ih "^MaxAuthTries" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set")"
        echo "AllowUsers              : $(grep -ih "^AllowUsers" $sshd_conf 2>/dev/null | tail -1 | cut -d: -f2- || echo "Not set")"
    fi
    print_sub "World Writable Files (Sample)"; echo "Scanning... (timeout: 30s)"; safe_find / -xdev -type f -perm -0002 2>/dev/null | head -50
    print_sub "World Writable Directories"; safe_find / -xdev -type d -perm -0002 2>/dev/null | head -30
    print_sub "SUID Files (Potential Privilege Escalation)"; safe_find / -xdev -type f -perm -4000 2>/dev/null | head -50
    print_sub "SGID Files"; safe_find / -xdev -type f -perm -2000 2>/dev/null | head -50
    print_sub "Files with No Owner/Group"; safe_find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null | head -30
    print_sub "Sysctl Security Parameters"
    local -a sysctl_params=("kernel.randomize_va_space" "net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.default.accept_redirects" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.default.rp_filter" "net.ipv4.icmp_echo_ignore_broadcasts" "net.ipv4.conf.all.accept_source_route" "net.ipv4.conf.default.accept_source_route" "net.ipv4.tcp_syncookies" "net.ipv4.conf.all.log_martians" "kernel.dmesg_restrict" "kernel.kptr_restrict" "fs.suid_dumpable")
    for param in "${sysctl_params[@]}"; do local value=$(sysctl -n "$param" 2>/dev/null) && echo "$param = $value" || echo "$param = (not available)"; done
    print_sub "Dangerous Dotfiles"; safe_find /home /root /tmp /var/tmp -maxdepth 3 \( -name ".rhosts" -o -name ".netrc" -o -name ".forward" \) -type f 2>/dev/null
    print_sub "Sensitive Directory Permissions"
    echo "/tmp    : $(ls -ld /tmp 2>/dev/null | awk '{print $1, $3, $4}')"; echo "/var/tmp: $(ls -ld /var/tmp 2>/dev/null | awk '{print $1, $3, $4}')"; echo "/dev/shm: $(ls -ld /dev/shm 2>/dev/null | awk '{print $1, $3, $4}')"
    print_sub "Missing Sticky Bit on World-Writable Directories"; safe_find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20
    print_sub "Password Hashing Algorithm"
    if [[ -r /etc/shadow ]]; then
        local hash_type=$(head -1 /etc/shadow 2>/dev/null | cut -d: -f2 | cut -c1-3)
        case "$hash_type" in '$1$') echo "WARNING: Using MD5 (weak!)" ;; '$5$') echo "OK: Using SHA-256" ;; '$6$') echo "OK: Using SHA-512 (recommended)" ;; '$y$') echo "OK: Using yescrypt (modern)" ;; *) echo "Unknown/Custom: $hash_type" ;; esac
    else echo "Cannot read /etc/shadow (root required)"; fi
    print_sub "SSH Authorized Keys"
    echo "--- Root ---"; if [[ -f /root/.ssh/authorized_keys ]]; then cat /root/.ssh/authorized_keys 2>/dev/null || echo "(not readable)"; echo ""; echo "Key count: $(wc -l < /root/.ssh/authorized_keys 2>/dev/null || echo 0)"; else echo "(no authorized_keys file)"; fi
    echo ""; echo "--- Users ---"; find /home -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do echo "=== $keyfile ==="; cat "$keyfile" 2>/dev/null; echo "Key count: $(wc -l < "$keyfile" 2>/dev/null || echo 0)"; echo ""; done
}

audit_webserver() {
    print_header "WEBSERVER CHECKS"
    local apache_service nginx_service apache_log_path
    apache_service=$(get_webserver_service_name "apache"); nginx_service=$(get_webserver_service_name "nginx"); apache_log_path=$(get_webserver_log_path "apache")
    print_sub "Apache/httpd Status"
    if systemctl is-active --quiet "$apache_service" 2>/dev/null || pgrep -x "$apache_service" &>/dev/null; then
        echo "[RUNNING] Service: $apache_service"; echo "Log path: $apache_log_path"
        if [[ -d "$apache_log_path" ]]; then
            echo ""; echo "--- Recent Access Logs (last 30 lines) ---"; for logfile in "$apache_log_path"/access*.log; do [[ -f "$logfile" ]] && { echo ">>> $logfile"; tail -n 30 "$logfile" 2>/dev/null; }; done
            echo ""; echo "--- Recent Error Logs (last 30 lines) ---"; for logfile in "$apache_log_path"/error*.log; do [[ -f "$logfile" ]] && { echo ">>> $logfile"; tail -n 30 "$logfile" 2>/dev/null; }; done
        fi
    else echo "[NOT RUNNING] $apache_service"; fi
    print_sub "Nginx Status"
    if systemctl is-active --quiet nginx 2>/dev/null || pgrep -x nginx &>/dev/null; then
        echo "[RUNNING] Service: nginx"; local nginx_log="/var/log/nginx"
        if [[ -d "$nginx_log" ]]; then
            echo ""; echo "--- Recent Access Logs (last 30 lines) ---"; for logfile in "$nginx_log"/access*.log; do [[ -f "$logfile" ]] && { echo ">>> $logfile"; tail -n 30 "$logfile" 2>/dev/null; }; done
            echo ""; echo "--- Recent Error Logs (last 30 lines) ---"; for logfile in "$nginx_log"/error*.log; do [[ -f "$logfile" ]] && { echo ">>> $logfile"; tail -n 30 "$logfile" 2>/dev/null; }; done
        fi
    else echo "[NOT RUNNING] nginx"; fi
    print_sub "Web Document Roots"
    local -a doc_roots=(/var/www/html /var/www /srv/www /usr/share/nginx/html /var/www/vhosts /srv/http)
    for docroot in "${doc_roots[@]}"; do [[ -d "$docroot" ]] && { echo "=== $docroot ==="; ls -la "$docroot" 2>/dev/null | head -20; echo ""; }; done
}

audit_suspicious_files() {
    print_header "SUSPICIOUS FILE CHECKS"
    print_sub "PHP Webshell Detection"
    local -a web_dirs=(/var/www /srv/www /usr/share/nginx/html /home /srv/http /opt)
    local -a php_patterns=("eval\(" "base64_decode\(" "shell_exec\(" "system\(" "exec\(" "passthru\(" "popen\(" "proc_open\(" "pcntl_exec\(" "assert\(" "preg_replace.*\/e" "create_function" "call_user_func")
    for webdir in "${web_dirs[@]}"; do if [[ -d "$webdir" ]]; then for pattern in "${php_patterns[@]}"; do find "$webdir" -type f -name "*.php" -exec grep -l "$pattern" {} \; 2>/dev/null | head -20; done; fi; done | sort -u | head -50
    print_sub "Suspicious .bat Files (Unusual on Linux)"; safe_find / -type f -name "*.bat" 2>/dev/null | head -20
    print_sub "Suspicious Shell Scripts"
    local -a shell_patterns=("curl " "wget " "nc " "netcat " "bash -i" "sh -i" "/dev/tcp" "mkfifo" "mknod" "socat TCP" "openssl s_client")
    for pattern in "${shell_patterns[@]}"; do find /tmp /var/tmp /dev/shm /home /root /opt -type f -name "*.sh" -exec grep -l "$pattern" {} \; 2>/dev/null; done | sort -u | head -30
    print_sub "Recently Modified Files in Sensitive Directories (7 days)"
    local -a sensitive_dirs=(/etc /usr/bin /usr/sbin /bin /sbin)
    for dir in "${sensitive_dirs[@]}"; do [[ -d "$dir" ]] && { echo "=== $dir ==="; safe_find "$dir" -type f -mtime -7 2>/dev/null | head -15; echo ""; }; done
    print_sub "Hidden Files in Temp Directories"; safe_find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null | head -30
    print_sub "Executable Files in Temp Directories"; safe_find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -30
    print_sub "Reverse Shell Indicators"
    local -a reverse_patterns=("bash -i" "sh -i" "/dev/tcp" "nc -e" "ncat -e" "socat TCP" "mkfifo" "openssl s_client" "python -c.*socket")
    for pattern in "${reverse_patterns[@]}"; do grep -r "$pattern" /tmp /var/tmp /dev/shm 2>/dev/null; done | head -30
    print_sub "Large Files in Temp Directories (>10MB)"; safe_find /tmp /var/tmp /dev/shm -type f -size +10M -exec ls -lh {} \; 2>/dev/null | head -20
}

audit_mining() {
    print_header "CRYPTOMINING CHECKS"
    local -a mining_patterns=("xmrig" "minerd" "cryptonight" "cpuminer" "coinhive" "cryptominer" "ethminer" "claymore" "phoenixminer" "t-rex" "nbminer" "gminer" "lolminer" "hiveon" "xmrig-proxy" "stratumproxy" "xmr-stak" "nanominer" "teamredminer" "tbminer")
    print_sub "Mining Processes"
    local mining_procs=$(ps aux 2>/dev/null | grep -iE "$(IFS='|'; echo "${mining_patterns[*]}")" | grep -v grep)
    if [[ -n "$mining_procs" ]]; then log_threat "HIGH" "CRYPTO_MINER" "Proses mining terdeteksi!" "Process"; echo "$mining_procs"; else echo "(no mining processes detected)"; fi
    print_sub "Mining Services"
    if command -v systemctl &>/dev/null; then
        local mining_services=$(systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -iE "$(IFS='|'; echo "${mining_patterns[*]}")")
        if [[ -n "$mining_services" ]]; then log_threat "HIGH" "MINER_SERVICE" "Service mining terdeteksi!"; echo "$mining_services"; else echo "(no mining services detected)"; fi
    fi
    print_sub "Mining-related Files"
    local -a mining_filenames=("*xmrig*" "*minerd*" "*cryptonight*" "*cpuminer*" "*xmr-stak*")
    for pattern in "${mining_filenames[@]}"; do safe_find / -type f -name "$pattern" 2>/dev/null; done | head -30
    print_sub "Connections to Common Mining Ports"
    local -a mining_ports=("4444" "3333" "5555" "14444" "45560" "45700" "8888" "7777" "9999" "3357")
    if command -v ss &>/dev/null; then for port in "${mining_ports[@]}"; do local conn=$(ss -tnp 2>/dev/null | grep ":$port "); [[ -n "$conn" ]] && log_threat "HIGH" "MINER_PORT" "Koneksi ke port mining ($port) terdeteksi!" "Network"; done; echo "(scan complete)"; fi
    print_sub "High CPU Processes (Potential Mining)"; ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>70 {print "SUSPICIOUS (CPU " $3 "%): " $11}' | head -10
    print_sub "Docker Containers for Mining"
    if command -v docker &>/dev/null; then local miner_cont=$(docker ps --format "{{.Names}}: {{.Image}}" 2>/dev/null | grep -iE "$(IFS='|'; echo "${mining_patterns[*]}")"); [[ -n "$miner_cont" ]] && log_threat "HIGH" "MINER_CONTAINER" "Container mining terdeteksi!"; fi
}

audit_containers() {
    print_header "CONTAINER & VIRTUALIZATION CHECKS"
    print_sub "Docker"
    if command -v docker &>/dev/null; then
        echo "--- Version ---"; docker version --format '{{.Server.Version}}' 2>/dev/null || docker version 2>/dev/null | head -10
        echo ""; echo "--- Running Containers ---"; docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
        echo ""; echo "--- All Containers ---"; docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null | head -30
        echo ""; echo "--- Images ---"; docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null | head -20
        echo ""; echo "--- Networks ---"; docker network ls 2>/dev/null; echo ""; echo "--- Volumes ---"; docker volume ls 2>/dev/null | head -20
        echo ""; echo "--- Privileged Containers ---"
        docker ps --format '{{.Names}}' 2>/dev/null | while read -r container; do
            if docker inspect "$container" 2>/dev/null | grep -q '"Privileged": true'; then log_threat "CRITICAL" "PRIV_CONTAINER" "Container '$container' berjalan mode Privileged!"; fi
        done
    else echo "(Docker not installed)"; fi
    print_sub "Podman"; if command -v podman &>/dev/null; then podman ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null; echo ""; podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null | head -20; else echo "(Podman not installed)"; fi
    print_sub "LXC/LXD"; if command -v lxc &>/dev/null; then lxc list 2>/dev/null || lxc-ls -fancy 2>/dev/null; else echo "(LXC/LXD not installed)"; fi
    print_sub "KVM/QEMU Virtual Machines"
    if command -v virsh &>/dev/null; then virsh list --all 2>/dev/null
    elif command -v qemu-system-x86_64 &>/dev/null; then echo "QEMU installed but libvirt not available"; ps aux 2>/dev/null | grep -i qemu | grep -v grep
    else echo "(KVM/QEMU not installed or not accessible)"; fi
}

audit_additional_security() {
    print_header "ADDITIONAL SECURITY CHECKS"
    print_sub "Kernel Modules (Suspicious)"
    local suspicious_modules=$(lsmod 2>/dev/null | grep -iE "hide|rootkit|kit|invisible|cloak")
    if [[ -n "$suspicious_modules" ]]; then log_threat "HIGH" "ROOTKIT_MODULE" "Modul mencurigakan ditemukan: $suspicious_modules"; echo "$suspicious_modules"; else echo "(no suspicious modules)"; fi
    print_sub "All Loaded Kernel Modules"; lsmod 2>/dev/null | head -40
    print_sub "LD_PRELOAD Check"; echo "Current LD_PRELOAD: ${LD_PRELOAD:-Not set}"
    if [[ -f /etc/ld.so.preload ]]; then log_threat "CRITICAL" "LD_PRELOAD_HIJACK" "File /etc/ld.so.preload ada! Potensi hijacking!" "/etc/ld.so.preload"; cat /etc/ld.so.preload 2>/dev/null; else echo "/etc/ld.so.preload: (not found - good)"; fi
    print_sub "Account Lockout Status"
    if command -v faillock &>/dev/null; then echo "--- Root ---"; faillock --user root 2>/dev/null || echo "(no lockouts)"; echo ""; echo "--- All Users ---"; faillock --all 2>/dev/null | head -30 || echo "(no lockouts)"
    elif [[ -f /var/log/btmp ]]; then echo "--- Failed logins (lastb) ---"; lastb 2>/dev/null | head -30; fi
    print_sub "USB Device History"; if [[ -f /var/log/dmesg ]]; then grep -i "usb\|sd[a-z]" /var/log/dmesg 2>/dev/null | tail -20; else dmesg 2>/dev/null | grep -i "usb" | tail -20 || echo "(cannot read dmesg)"; fi
    print_sub "Recently Installed Packages"
    local pkg_manager=$(get_package_manager)
    case "$pkg_manager" in
        apt) [[ -f /var/log/dpkg.log ]] && grep " install " /var/log/dpkg.log 2>/dev/null | tail -30 ;;
        dnf|yum) rpm -qa --last 2>/dev/null | head -30 ;; pacman) pacman -Qe 2>/dev/null | head -30 ;;
        zypper) zypper search -i --sort-by-name 2>/dev/null | head -30 ;; apk) apk info 2>/dev/null | head -30 ;; *) echo "(unknown package manager)" ;;
    esac
    print_sub "Security Updates Available"
    case "$pkg_manager" in
        apt) apt list --upgradable 2>/dev/null | head -20 ;; dnf) dnf check-update --quiet 2>/dev/null | head -20 ;;
        yum) yum check-update 2>/dev/null | head -20 ;; pacman) pacman -Qu 2>/dev/null | head -20 ;;
        zypper) zypper list-updates 2>/dev/null | head -20 ;; apk) apk upgrade --simulate 2>/dev/null | head -20 ;; *) echo "(cannot check updates)" ;;
    esac
    print_sub "SSH Host Keys"; echo "--- Fingerprint Check ---"; for keyfile in /etc/ssh/ssh_host_*_key.pub; do [[ -f "$keyfile" ]] && { echo "$keyfile:"; ssh-keygen -l -f "$keyfile" 2>/dev/null; }; done
    print_sub "AT Jobs (Scheduled Tasks)"; if command -v atq &>/dev/null; then atq 2>/dev/null || echo "(no at jobs)"; else echo "(at not installed)"; fi
    print_sub "Systemd User Services"; if command -v systemctl &>/dev/null; then for user_dir in /home/*/.config/systemd/user /root/.config/systemd/user; do [[ -d "$user_dir" ]] && { echo "=== $user_dir ==="; ls -la "$user_dir"/*.service 2>/dev/null | head -20; }; done; fi
}

# ==================== ANTIVIRUS & BACKDOOR SCANNER ====================
audit_antivirus_backdoor() {
    print_header "ANTIVIRUS: ADVANCED BACKDOOR & POLYGLOT SCANNER"
    echo -e "${MAGENTA}Memindai file menyamar (PDF/Image berisi script), Hidden Payload, dan Persistence...${NC}"
    
    local -a scan_locations=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/srv/www" "/opt")
    local -a find_safe_excludes=(
        -not -path "*/.git/*" 
        -not -path "*/.svn/*" 
        -not -path "*/.hg/*" 
        -not -path "*/node_modules/*" 
        -not -path "*/vendor/*" 
        -not -path "*/__pycache__/*"
        -not -path "*/.cache/*"
    )
    local -a safe_text_exts=(
        -not -name "*.sample" 
        -not -name "*.bak" 
        -not -name "*.old" 
        -not -name "*.save" 
        -not -name "*.txt" 
        -not -name "*.log" 
        -not -name "*.md" 
        -not -name "*.json" 
        -not -name "*.xml" 
        -not -name "*.html" 
        -not -name "*.yml" 
        -not -name "*.yaml" 
        -not -name "*.toml" 
        -not -name "*.cfg" 
        -not -name "*.ini" 
        -not -name "*.conf" 
        -not -name "*.env*"
        -not -name "*.csv"
    )

    # 1. POLYGOT FILE DETECTION
    print_sub "Deteksi File Polyglot (Hoax PDF/Image)"
    for loc in "/tmp" "/var/tmp" "/dev/shm"; do
        [[ -d "$loc" ]] || continue
        while IFS= read -r -d '' file; do
            local header=$(xxd -l 5 -p "$file" 2>/dev/null)
            if [[ "$header" != "255044462d" ]]; then
                log_threat "CRITICAL" "POLYGLOT_PDF" "File PDF BUKAN format asli. Backdoor RCE menyamar!" "$file"
            fi
        done < <(find "$loc" -type f -name "*.pdf" -size +1k -size -10M -print0 2>/dev/null)
        
        while IFS= read -r -d '' file; do
            local header=$(xxd -l 4 -p "$file" 2>/dev/null)
            if [[ "$header" != "89504e47" && "$header" != "ffd8ffe0" && "$header" != "ffd8ffe1" ]]; then
                log_threat "CRITICAL" "POLYGLOT_IMG" "File Gambar BUKAN format asli. Backdoor RCE menyamar!" "$file"
            fi
        done < <(find "$loc" -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" \) -size +1k -size -10M -print0 2>/dev/null)
    done

    # 2. SHELL BACKDOOR MENYUSUP
    print_sub "Deteksi Script Backdoor Menyamar"
    for loc in "/home" "/root"; do
        [[ -d "$loc" ]] || continue
        while IFS= read -r -d '' file; do
            if file "$file" 2>/dev/null | grep -qi "text"; then
                local first_line=$(head -n 1 "$file" 2>/dev/null)
                if [[ "$first_line" =~ ^#!.*bash ]] || [[ "$first_line" =~ ^#!.*/sh ]]; then
                    log_threat "HIGH" "SHELL_DISGUISE" "File teks non-script berisi shebang bash. Potensi RCE." "$file"
                fi
            fi
        done < <(find "$loc" -maxdepth 5 -type f \( -name "*.txt" -o -name "*.jpg" -o -name "*.png" -o -name "*.pdf" -o -name "*.jpeg" -o -name "*.gif" \) "${find_safe_excludes[@]}" -size +0 -size -2M -print0 2>/dev/null)
    done

    # 3. DEEP PAYLOAD TERSEMBUNYI (Regex)
    print_sub "Deep Scan: Encoded Payloads & Obfuscated Commands"
    local -a encoded_patterns=(
        "bash -i\b"
        "sh -i\b"
        "/dev/tcp/"
        "/dev/udp/"
        "mkfifo\s"
        "mknod\s"
        "python -c\s.*import\s+(socket|os|subprocess|pty)"
        "perl -e\s.*socket"
        "ruby -e\s.*socket"
        "eval\(\s*\\\$"
        "base64\s+-d\s+\|\s+"
        "curl\s+[^\s]+\s+-[soO]\s+\|\s+(ba)?sh\b"
        "wget\s+[^\s]+\s+-O\s+-\s+\|\s+(ba)?sh\b"
        "fetch\s+-o\s+-\s+\|\s+(ba)?sh\b"
        "openssl\s+s_client\s+"
        "socat\s+(TCP|UDP|EXEC)"
    )
    
    local -a detected_files=() 
    
    for loc in "${scan_locations[@]}"; do
        [[ -d "$loc" ]] || continue
        for pattern in "${encoded_patterns[@]}"; do
            local -a found_files=()
            mapfile -t found_files < <(grep -rl -E "$pattern" "$loc" 2>/dev/null --include="*.sh" --include="*.bash" --include="*.py" --include="*.pl" --include="*.rb" --include="*.conf" --include="*.service" --include="*.timer")
            
            for infected_file in "${found_files[@]}"; do
                [[ -z "$infected_file" ]] && continue
                [[ "$(stat -c%s "$infected_file" 2>/dev/null)" -gt 1048576 ]] && continue
                
                local is_dup="0"
                for cached in "${detected_files[@]}"; do
                    if [[ "$cached" == "$infected_file" ]]; then is_dup="1"; break; fi
                done
                [[ "$is_dup" == "1" ]] && continue
                
                detected_files+=("$infected_file")
                log_threat "HIGH" "HIDDEN_PAYLOAD" "Pola payload tersembunyi: $pattern" "$infected_file"
            done
        done
    done

    # 4. PERSISTENCE: SYSTEMD & CRON TROJAN
    print_sub "Persistence: Systemd & Cron Trojan Scan"
    local -a target_svc_paths=("/etc/systemd/system" "/run/systemd/system")
    for s_path in "${target_svc_paths[@]}"; do
        [[ -d "$s_path" ]] || continue
        local -a found_svcs=()
        mapfile -t found_svcs < <(grep -rl -E "ExecStart=.*/tmp/|ExecStart=.*/dev/shm/|ExecStart=.*curl\s+[^\s]+\s+-[soO]\s+\|\s+|ExecStart=.*wget\s+[^\s]+\s+-O\s+-\s+\|\s+|ExecStart=.*bash\s+-c\s.*curl|ExecStart=.*bash\s+-c\s.*wget" "$s_path" 2>/dev/null)
        
        for svc in "${found_svcs[@]}"; do
            [[ -z "$svc" ]] && continue 
            log_threat "CRITICAL" "SYSTEMD_TROJAN" "Service systemd mengeksekusi payload mencurigakan!" "$svc"
        done
    done

    for cron_file in /etc/crontab /etc/cron.d/*; do
        [[ -f "$cron_file" ]] || continue
        if grep -qiE "curl\s+[^\s]+\s+-[soO]\s+\|\s+|wget\s+[^\s]+\s+-O\s+-\s+\|\s+|bash\s+-i\b|/dev/tcp/|base64\s+-d\s+\|" "$cron_file" 2>/dev/null; then
            log_threat "CRITICAL" "CRON_TROJAN" "Cronjob sistem mengandung pola backdoor!" "$cron_file"
        fi
    done

    # 5. SSH BINARY WRAPPER CHECK
    print_sub "SSH Binary Integrity Check"
    local ssh_bins=$(which sshd 2>/dev/null)
    if [[ -n "$ssh_bins" ]]; then
        if file "$ssh_bins" 2>/dev/null | grep -qi "script\|text"; then
            log_threat "CRITICAL" "SSH_WRAPPER" "Binary sshd adalah FILE TEXT/SCRIPT! 100% Backdoor Wrapper!" "$ssh_bins"
        fi
    fi
}

# ==================== KUBERNETES SECURITY AUDIT ====================
audit_kubernetes() {
    print_header "KUBERNETES (K8s) SECURITY AUDIT"
    local is_k8s=false
    [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]] && is_k8s=true
    command -v kubectl &>/dev/null && is_k8s=true

    if [[ "$is_k8s" == false ]]; then echo "(Bukan environment Kubernetes)"; return; fi
    echo -e "${GREEN}[i] Environment Kubernetes terdeteksi${NC}"

    print_sub "Service Account Token Exposure"
    if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        local sa_perms=$(stat -c "%a" "/var/run/secrets/kubernetes.io/serviceaccount/token" 2>/dev/null)
        if [[ "$sa_perms" -gt 600 ]]; then
            log_threat "HIGH" "K8S_SA_EXPOSE" "Service Account Token bisa dibaca selain owner ($sa_perms)!" "/var/run/secrets/kubernetes.io/serviceaccount/token"
        else echo "SA Token Permissions: OK ($sa_perms)"; fi
    fi

    print_sub "Kubeconfig Security"
    local kubeconf="${KUBECONFIG:-$HOME/.kube/config}"
    if [[ -f "$kubeconf" ]]; then
        local kc_perms=$(stat -c "%a" "$kubeconf" 2>/dev/null)
        if [[ "$kc_perms" -gt 600 ]]; then
            log_threat "HIGH" "K8S_CONFIG_LEAK" "File Kubeconfig memiliki permission terlalu longgar ($kc_perms). Harus 600." "$kubeconf"
        fi
    fi

    print_sub "K8s Cluster Resource Security (Requires kubectl)"
    if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null; then
        echo "--- Checking Privileged Pods ---"
        local priv_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | grep -iE '"privileged": true|"hostPID": true|"hostNetwork": true')
        if [[ -n "$priv_pods" ]]; then log_threat "CRITICAL" "K8S_PRIV_POD" "Ditemukan Pod dengan akses Privileged/hostPID/hostNetwork!"; else echo "(No privileged pods found)"; fi
        echo "--- Checking Risky RBAC Bindings ---"; kubectl get clusterrolebindings,rolebindings --all-namespaces -o wide 2>/dev/null | grep -iE "cluster-admin|system:masters" | head -20
    else echo "(Cannot query cluster via kubectl)"; fi
}

# ==================== CI/CD PIPELINE SECURITY ====================
audit_cicd() {
    print_header "CI/CD PIPELINE SECURITY AUDIT"
    local found_cicd=false

    print_sub "Jenkins Security"
    if pgrep -f "jenkins.war" &>/dev/null || systemctl is-active --quiet jenkins 2>/dev/null; then
        found_cicd=true; echo -e "${YELLOW}[Jenkins Terdeteksi]${NC}"
        if [[ -f /var/lib/jenkins/credentials.xml ]] && grep -q "<password>" /var/lib/jenkins/credentials.xml 2>/dev/null; then
            log_threat "CRITICAL" "CICD_JENKINS_CREDS" "Password Jenkins ditemukan dalam plain text!" "/var/lib/jenkins/credentials.xml"
        fi
        local -a jenkins_jobs=()
        mapfile -t jenkins_jobs < <(find /var/lib/jenkins/jobs -name "*.xml" -exec grep -l "groovy.*Runtime.*exec\|ProcessBuilder" {} \; 2>/dev/null)
        for job in "${jenkins_jobs[@]}"; do
            [[ -n "$job" ]] && log_threat "HIGH" "CICD_JENKINS_RCE" "Job Jenkins mengandung eksekusi system berbahaya!" "$job"
        done
    fi

    print_sub "GitLab Runner Security"
    if command -v gitlab-runner &>/dev/null || systemctl is-active --quiet gitlab-runner 2>/dev/null; then
        found_cicd=true; echo -e "${YELLOW}[GitLab Runner Terdeteksi]${NC}"
        local runner_conf="/etc/gitlab-runner/config.toml"
        if [[ -f "$runner_conf" ]] && grep -q "privileged\s*=\s*true" "$runner_conf" 2>/dev/null; then
            log_threat "CRITICAL" "CICD_GL_PRIV" "GitLab Runner berjalan mode PRIVILEGED! Rentan Container Escape." "$runner_conf"
        fi
    fi

    print_sub "GitHub Actions Runner Security"
    if pgrep -f "actions.runner" &>/dev/null || [[ -d /runner ]]; then
        found_cicd=true; echo -e "${YELLOW}[GitHub Actions Runner Terdeteksi]${NC}"
        if env | grep -qE "^GITHUB_TOKEN="; then log_threat "HIGH" "CICD_GH_TOKEN" "GITHUB_TOKEN terekspose di environment variables!"; fi
    fi

    [[ "$found_cicd" == false ]] && echo "(Tidak ada CI/CD engine terdeteksi pada server ini)"
}

# ==================== MAIN AUDIT FUNCTION ====================
perform_audit() {
    local separator="═══════════════════════════════════════════════════════════════════════════════"
    echo "$separator"
    echo "  LINUX SECURITY & MALWARE AUDIT REPORT"
    echo "  Generated : $(date)"; echo "  Host      : $HOSTNAME_VAR"; echo "  Version   : $SCRIPT_VERSION"
    echo "$separator"
    local distro_info=$(detect_distro)
    echo ""; echo "Distribution : $(echo "$distro_info" | cut -d'|' -f1)"; echo "Version      : $(echo "$distro_info" | cut -d'|' -f2)"
    echo "Family       : $(echo "$distro_info" | cut -d'|' -f3)"; echo "Arch         : $(uname -m 2>/dev/null || echo 'unknown')"; echo "Kernel       : $(uname -r 2>/dev/null || echo 'unknown')"
    
    audit_system_information; audit_users_and_groups; audit_networking; audit_services; audit_security
    audit_webserver; audit_suspicious_files; audit_mining; audit_containers; audit_additional_security
    audit_antivirus_backdoor; audit_kubernetes; audit_cicd
    
    echo ""; echo "$separator"
    echo "  AUDIT COMPLETED"; echo "  End Time : $(date)"; echo "  Duration : $SECONDS seconds"
    echo "$separator"; echo ""
    
    if [[ $THREAT_COUNT -gt 0 ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  [!!!] PERINGATAN KEAMANAN: $THREAT_COUNT ANCAMAN TERDETEKSI                       ║${NC}"
        echo -e "${RED}║  Lihat detail ancaman di: $THREAT_LOG${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  [✓] SYSTEM CLEAN: Tidak ada ancaman/backdoor terdeteksi                        ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    fi
}

# ==================== SCRIPT ENTRY POINT ====================
main() {
    tput clear 2>/dev/null || clear 2>/dev/null || true
    echo "  ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗     ██╗   ██╗██████╗  "
    echo "  ██║     ██║████╗  ██║██║   ██╗╚██╗██╔╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║     ██║   ██║██╔══██╗ "
    echo "  ██║     ██║██╔██╗ ██║██╗   ██╗ ╚███╔╝ ███████║██║   ██╗██║  ██║██║   ██║   ██║     ██║   ██║██████╔╝ "
    echo "  ██║     ██║██║╚██╗██║██╗   ██╗ ██╔██╗ ██╔══██╗██║   ██╗██║  ██║██║   ██║   ██║     ██║   ██║██╔══██╗ "
    echo "  ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗██║  ██║╚██████╔╝██████╔╝██║   ██║   ███████╗╚██████╔╝██║  ██║ "
    echo "  ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ "
    echo ""
    echo -e "${BOLD}Gagaltotal666 | Linux Security & Antivirus Audit Script v$SCRIPT_VERSION${NC}"
    echo ""
    echo -e "${CYAN}Dukungan Multi-Distro & Infrastruktur:${NC}"
    echo "  • Debian/Ubuntu/Mint/Kali/Parrot (Debian Family)"
    echo "  • RHEL/CentOS/Rocky/Alma/Fedora/Oracle Linux (RHEL Family)"
    echo "  • Arch Linux/Manjaro/EndeavourOS (Arch Family)"
    echo "  • openSUSE/SLES (SUSE Family)"
    echo "  • Alpine Linux, Gentoo, Void, Slackware"
    echo "  • Kubernetes Environment (Pod/Node), Docker, LXC, KVM/QEMU"
    echo "  • CI/CD Engines (Jenkins, GitLab Runner, GitHub Actions)"
    echo ""; echo -e "${YELLOW}Catatan: Beberapa cek membutuhkan akses root untuk hasil lengkap${NC}"; echo ""
    
    detect_distro > /dev/null; local distro_info=$(detect_distro)
    echo -e "Distro terdeteksi: ${GREEN}$(echo "$distro_info" | cut -d'|' -f1)${NC}"
    echo -e "Keluarga          : ${GREEN}$(echo "$distro_info" | cut -d'|' -f3)${NC}"; echo ""
    
    if [[ $EUID -eq 0 ]]; then echo -e "${GREEN}[✓] Berjalan sebagai root - Akses penuh & Mode Antivirus Aktif${NC}"
    else echo -e "${YELLOW}[!] Tidak berjalan sebagai root - Beberapa cek mungkin terbatas${NC}"; fi
    echo ""; read -p "Tekan Enter untuk memulai audit... " -r
    
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then echo -e "${RED}Error: Tidak bisa membuat direktori $OUTPUT_DIR${NC}" >&2; exit 1; fi
    echo ""; echo -e "${GREEN}Output akan disimpan ke: $OUTPUT_FILE${NC}"; echo ""; SECONDS=0
    echo -e "${CYAN}[~] Memulai audit...${NC}"; echo ""
    
    perform_audit 2>&1 | tee "$TEMP_OUTPUT"
    
    if [[ -f "$TEMP_OUTPUT" ]] && [[ -s "$TEMP_OUTPUT" ]]; then
        if command -v sed &>/dev/null; then sed 's/\x1b\[[0-9;]*m//g' "$TEMP_OUTPUT" > "$OUTPUT_FILE"; else cp "$TEMP_OUTPUT" "$OUTPUT_FILE"; fi
        if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
            echo ""; echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}  ✓ Audit selesai!${NC}"
            echo -e "${GREEN}  Log Utama       : $OUTPUT_FILE${NC}"
            echo -e "${RED}  Log Ancaman     : $THREAT_LOG (Jika ada ancaman)${NC}"
            echo -e "${GREEN}  Ukuran file    : $(du -h "$OUTPUT_FILE" | cut -f1)${NC}"
            echo -e "${GREEN}  Waktu eksekusi : $SECONDS detik${NC}"
            echo -e "${GREEN}  Selesai pada   : $(date)${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
        else echo -e "${RED}ERROR: Gagal membuat file output final${NC}" >&2; echo -e "${YELLOW}File temporary tersedia di: $TEMP_OUTPUT${NC}" >&2; fi
    else echo -e "${RED}ERROR: Gagal membuat file temporary${NC}" >&2; fi
    
    if [[ -f "$LOG_FILE" ]] && [[ -s "$LOG_FILE" ]]; then echo ""; echo -e "${YELLOW}[!] Ada error selama audit. Detail: $LOG_FILE${NC}"; echo -e "${YELLOW}    Jumlah error: $(wc -l < "$LOG_FILE")${NC}"; fi
}

main "$@"