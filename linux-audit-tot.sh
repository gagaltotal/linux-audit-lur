#!/bin/bash
# ============================================================================
# Linux Security Audit Script - Gagaltotal666
# Version: 2.0 - Multi-Distro Support
# Supported: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, SUSE, Alpine, dll
# ============================================================================

# Strict mode dengan pengecualian yang aman
set -o pipefail
# Tidak menggunakan 'set -e' karena banyak perintah yang boleh gagal

# ==================== GLOBAL VARIABLES ====================
readonly SCRIPT_VERSION="2.0"
readonly TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
readonly HOSTNAME_VAR=$(hostname 2>/dev/null || echo "unknown")
readonly OUTPUT_DIR="LinuxAudit-${HOSTNAME_VAR}-${TIMESTAMP}"
readonly OUTPUT_FILE="${OUTPUT_DIR}/LinuxAudit.txt"
readonly LOG_FILE="${OUTPUT_DIR}/audit_errors.log"
DISTRO_FAMILY=""

# ==================== COLOR DEFINITIONS ====================
if [[ -t 1 ]] && command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    NC='\033[0m'
    BOLD='\033[1m'
    DIM='\033[2m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' NC='' BOLD='' DIM=''
fi

# ==================== TRAP HANDLERS ====================
trap 'cleanup' EXIT
trap 'ctrl_c' INT TERM

cleanup() {
    local exit_code=$?
    if [[ -f "$LOG_FILE" ]] && [[ -s "$LOG_FILE" ]]; then
        echo -e "\n${YELLOW}[!] Error log tersimpan di: $LOG_FILE${NC}" >&2
    else
        rm -f "$LOG_FILE" 2>/dev/null
    fi
    exit $exit_code
}

ctrl_c() {
    echo -e "\n${RED}** Anda menekan Ctrl+C... Keluar${NC}" >&2
    exit 130
}

# ==================== UTILITY FUNCTIONS ====================
# Logging error tanpa menghentikan script
log_error() {
    echo "[ERROR][$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true
}

# Safe exec - menjalankan perintah dengan error handling
safe_exec() {
    if [[ $# -eq 0 ]]; then
        log_error "safe_exec dipanggil tanpa argumen"
        return 1
    fi
    
    local cmd="$1"
    shift
    
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Perintah tidak ditemukan: $cmd"
        return 127
    fi
    
    "$cmd" "$@" 2>>"$LOG_FILE"
    local status=$?
    
    if [[ $status -ne 0 ]] && [[ $status -ne 141 ]]; then
        log_error "Gagal menjalankan: $cmd $* (exit code: $status)"
    fi
    
    return $status
}

# Safe find - dengan timeout dan error handling
safe_find() {
    local start_dir="${1:-/}"
    shift
    
    if ! command -v find &>/dev/null; then
        log_error "find tidak tersedia"
        return 127
    fi
    
    timeout 30 find "$start_dir" "$@" 2>/dev/null
    local status=$?
    
    if [[ $status -eq 124 ]]; then
        echo "[TIMEOUT] Pencarian dibatalkan setelah 30 detik"
        log_error "find timeout: $*"
    fi
    
    return 0
}

# Print section header
print_header() {
    local title="$1"
    local line="═══════════════════════════════════════════════════════════════════════════════"
    printf "\n${CYAN}%s${NC}\n" "$line"
    printf "${BOLD}[+] %s${NC}\n" "$title"
    printf "${CYAN}%s${NC}\n" "$line"
}

# Print sub-header
print_sub() {
    printf "\n${GREEN}[+] %s${NC}\n" "$1"
}

# ==================== DISTRO DETECTION ====================
detect_distro() {
    local distro=""
    local version=""
    local family=""
    local id=""
    
    # Method 1: /etc/os-release (standar modern)
    if [[ -f /etc/os-release ]]; then
        while IFS='=' read -r key value; do
            value="${value#\"}"
            value="${value%\"}"
            case "$key" in
                NAME) distro="$value" ;;
                VERSION) version="$value" ;;
                ID) id="$value" ;;
            esac
        done < /etc/os-release
        
        case "$id" in
            ubuntu|debian|linuxmint|pop|kali|parrot|mx)
                family="debian"
                ;;
            centos|rhel|fedora|rocky|almalinux|ol|oraclelinux|scientific)
                family="rhel"
                ;;
            arch|manjaro|endeavouros|garuda|cachyos)
                family="arch"
                ;;
            opensuse-leap|opensuse-tumbleweed|sles|sle-hpc)
                family="suse"
                ;;
            alpine)
                family="alpine"
                ;;
            gentoo|funtoo)
                family="gentoo"
                ;;
            void)
                family="void"
                ;;
            slackware)
                family="slackware"
                ;;
            *)
                family="other"
                ;;
        esac
    # Method 2: Red Hat specific
    elif [[ -f /etc/redhat-release ]]; then
        distro=$(cat /etc/redhat-release 2>/dev/null)
        family="rhel"
    # Method 3: SUSE specific
    elif [[ -f /etc/SuSE-release ]]; then
        distro=$(cat /etc/SuSE-release 2>/dev/null | head -1)
        family="suse"
    # Method 4: Arch specific
    elif [[ -f /etc/arch-release ]]; then
        distro="Arch Linux"
        family="arch"
    # Method 5: Alpine specific
    elif [[ -f /etc/alpine-release ]]; then
        distro="Alpine Linux $(cat /etc/alpine-release 2>/dev/null)"
        family="alpine"
    # Method 6: Gentoo specific
    elif [[ -f /etc/gentoo-release ]]; then
        distro=$(cat /etc/gentoo-release 2>/dev/null)
        family="gentoo"
    # Method 7: Slackware specific
    elif [[ -f /etc/slackware-version ]]; then
        distro="Slackware $(cat /etc/slackware-version 2>/dev/null)"
        family="slackware"
    else
        distro="Unknown Distribution"
        family="unknown"
    fi
    
    distro="${distro:-Unknown}"
    version="${version:-Unknown}"
    family="${family:-unknown}"
    
    DISTRO_FAMILY="$family"
    
    echo "${distro}|${version}|${family}"
}

# ==================== DISTRO-SPECIFIC HELPERS ====================
get_webserver_log_path() {
    local server="$1"
    local family="${DISTRO_FAMILY:-debian}"
    
    case "$server" in
        apache|httpd)
            case "$family" in
                debian|alpine) echo "/var/log/apache2" ;;
                rhel|suse|arch|*) echo "/var/log/httpd" ;;
            esac
            ;;
        nginx)
            echo "/var/log/nginx"
            ;;
        *)
            echo ""
            ;;
    esac
}

get_webserver_service_name() {
    local server="$1"
    local family="${DISTRO_FAMILY:-debian}"
    
    case "$server" in
        apache|httpd)
            case "$family" in
                debian|alpine) echo "apache2" ;;
                rhel|suse|arch|*) echo "httpd" ;;
            esac
            ;;
        nginx)
            echo "nginx"
            ;;
        *)
            echo ""
            ;;
    esac
}

get_package_manager() {
    local family="${DISTRO_FAMILY:-unknown}"
    
    case "$family" in
        debian) echo "apt" ;;
        rhel) echo "yum" ;;
        arch) echo "pacman" ;;
        suse) echo "zypper" ;;
        alpine) echo "apk" ;;
        fedora) echo "dnf" ;;
        *) echo "unknown" ;;
    esac
}

get_auth_log_path() {
    local family="${DISTRO_FAMILY:-unknown}"
    
    case "$family" in
        debian)
            echo "/var/log/auth.log"
            ;;
        rhel|suse|arch|*)
            echo "/var/log/secure"
            ;;
    esac
}

# ==================== MAIN AUDIT FUNCTIONS ====================
audit_system_information() {
    print_header "LINUX SYSTEM INFORMATION"
    
    print_sub "Linux Kernel Information"
    safe_exec uname -a
    
    print_sub "Linux Distribution Information"
    local distro_info
    distro_info=$(detect_distro)
    local distro_name version distro_family
    distro_name=$(echo "$distro_info" | cut -d'|' -f1)
    version=$(echo "$distro_info" | cut -d'|' -f2)
    distro_family=$(echo "$distro_info" | cut -d'|' -f3)
    
    echo "Distro       : $distro_name"
    echo "Version      : $version"
    echo "Family       : $distro_family"
    echo "Architecture : $(uname -m 2>/dev/null || echo 'unknown')"
    
    print_sub "Uptime Information"
    safe_exec uptime
    
    print_sub "CPU Information"
    if command -v lscpu &>/dev/null; then
        lscpu 2>/dev/null | grep -E "^(Architecture|CPU\(s\)|Model name|Thread|Core|Socket|CPU MHz|Cache size|Virtualization)" || true
    else
        safe_exec cat /proc/cpuinfo 2>/dev/null | grep -E "^(model name|processor|cpu cores|cpu MHz)" | head -20
    fi
    
    print_sub "Disk Space Usage"
    if command -v df &>/dev/null; then
        df -hT 2>/dev/null || df -h 2>/dev/null
    fi
    
    print_sub "Disk Usage by Directory (Top 15)"
    safe_exec du -h --max-depth=1 / 2>/dev/null | sort -rh | head -15
    
    print_sub "Memory Information"
    if command -v free &>/dev/null; then
        free -h 2>/dev/null
    else
        safe_exec cat /proc/meminfo 2>/dev/null | head -15
    fi
    
    print_sub "Swap Information"
    if command -v swapon &>/dev/null; then
        swapon --show 2>/dev/null || cat /proc/swaps 2>/dev/null
    elif [[ -f /proc/swaps ]]; then
        cat /proc/swaps
    fi
    
    print_sub "TCP Wrappers Configuration"
    echo "--- /etc/hosts.allow ---"
    if [[ -f /etc/hosts.allow ]]; then
        cat /etc/hosts.allow 2>/dev/null || echo "(empty or not readable)"
    else
        echo "(file not found)"
    fi
    echo ""
    echo "--- /etc/hosts.deny ---"
    if [[ -f /etc/hosts.deny ]]; then
        cat /etc/hosts.deny 2>/dev/null || echo "(empty or not readable)"
    else
        echo "(file not found)"
    fi
    
    print_sub "Cron Jobs"
    echo "--- User Crontabs ---"
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 ]] || [[ $uid -eq 0 ]]; then
            local crontab_content
            crontab_content=$(crontab -l -u "$username" 2>/dev/null) && {
                echo "[$username ($uid)]:"
                echo "$crontab_content"
                echo ""
            }
        fi
    done < /etc/passwd
    
    echo "--- System Crontab ---"
    if [[ -f /etc/crontab ]]; then
        safe_exec cat /etc/crontab
    fi
    
    echo ""
    echo "--- Cron Directories ---"
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$cron_dir" ]]; then
            echo ""
            echo "=== $cron_dir ==="
            safe_exec ls -la "$cron_dir" 2>/dev/null
        fi
    done
    
    print_sub "Systemd Timers"
    if command -v systemctl &>/dev/null; then
        systemctl list-timers --all --no-pager 2>/dev/null | head -30
    fi
    
    print_sub "Last Reboots"
    if command -v last &>/dev/null; then
        last reboot 2>/dev/null | head -15
    elif command -v journalctl &>/dev/null; then
        journalctl --list-boots --no-pager 2>/dev/null | head -15
    fi
    
    print_sub "System Load Average"
    if [[ -f /proc/loadavg ]]; then
        cat /proc/loadavg
    fi
    
    print_sub "Environment Variables (Security Relevant)"
    env 2>/dev/null | grep -iE "^(PATH|LD_PRELOAD|PYTHONPATH|PERL5LIB|CLASSPATH|LD_LIBRARY_PATH|PROMPT_COMMAND|BASH_FUNC)=" || echo "(none found)"
}

audit_users_and_groups() {
    print_header "USERS AND GROUPS CHECKS"
    
    print_sub "Current User Information"
    echo "User   : $(whoami 2>/dev/null || echo 'unknown')"
    echo "ID     : $(id 2>/dev/null || echo 'unknown')"
    echo "Groups : $(groups 2>/dev/null || echo 'unknown')"
    
    print_sub "Currently Logged In Users"
    safe_exec w
    
    print_sub "Login History (Last 20)"
    if command -v last &>/dev/null; then
        last -20 2>/dev/null
    fi
    
    print_sub "Failed Login Attempts"
    local auth_log
    auth_log=$(get_auth_log_path)
    
    if command -v journalctl &>/dev/null && [[ -d /var/log/journal ]]; then
        journalctl -u sshd --since "7 days ago" --no-pager 2>/dev/null | grep -iE "failed|invalid" | tail -50 || true
    elif [[ -f "$auth_log" ]]; then
        grep -iE "failed|invalid" "$auth_log" 2>/dev/null | tail -50 || true
    elif [[ -f /var/log/messages ]]; then
        grep -iE "failed|invalid" /var/log/messages 2>/dev/null | tail -30 || true
    else
        echo "(auth log not found)"
    fi
    
    print_sub "All Users with Login Shells"
    printf "%-20s %-8s %-15s %-30s\n" "USERNAME" "UID" "GID" "SHELL"
    printf "%-20s %-8s %-15s %-30s\n" "--------" "---" "---" "-----"
    while IFS=: read -r username _ uid gid _ home shell; do
        # Skip nologin shells
        case "$shell" in
            */nologin|*/false|*/sync|*/halt|*/shutdown) continue ;;
        esac
        printf "%-20s %-8s %-15s %-30s\n" "$username" "$uid" "$gid" "$shell"
    done < /etc/passwd
    
    print_sub "Users with UID 0 (Root Equivalent)"
    local uid0_users
    uid0_users=$(awk -F: '($3 == 0){print $1}' /etc/passwd 2>/dev/null)
    if [[ -n "$uid0_users" ]]; then
        echo "$uid0_users" | while read -r user; do
            if [[ "$user" != "root" ]]; then
                echo "${RED}WARNING: $user has UID 0!${NC}"
            else
                echo "root (expected)"
            fi
        done
    fi
    
    print_sub "Empty Password Check"
    if [[ -r /etc/shadow ]]; then
        local empty_pass
        empty_pass=$(awk -F: '($2 == "" || $2 == "!"){print $1}' /etc/shadow 2>/dev/null)
        if [[ -n "$empty_pass" ]]; then
            echo "${RED}WARNING: Users with empty or disabled passwords:${NC}"
            echo "$empty_pass"
        else
            echo "(no empty passwords found)"
        fi
    else
        echo "${YELLOW}Cannot read /etc/shadow (root required)${NC}"
    fi
    
    print_sub "Password Policy (/etc/login.defs)"
    if [[ -f /etc/login.defs ]]; then
        grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD)" /etc/login.defs 2>/dev/null || echo "(no policy found)"
    else
        echo "(file not found)"
    fi
    
    print_sub "Groups with Members"
    echo "--- /etc/group entries with members ---"
    while IFS=: read -r group _ gid members; do
        if [[ -n "$members" ]]; then
            echo "$group ($gid): $members"
        fi
    done < /etc/group
    
    print_sub "Sudoers Configuration"
    if [[ -d /etc/sudoers.d ]]; then
        echo "--- /etc/sudoers.d/ contents ---"
        ls -la /etc/sudoers.d/ 2>/dev/null
        echo ""
        for sudofile in /etc/sudoers.d/*; do
            if [[ -f "$sudofile" ]]; then
                echo "=== $sudofile ==="
                grep -vE '^#|^$' "$sudofile" 2>/dev/null || true
                echo ""
            fi
        done
    fi
    echo "--- /etc/sudoers (active lines) ---"
    if [[ -r /etc/sudoers ]]; then
        grep -vE '^#|^$|^Defaults' /etc/sudoers 2>/dev/null || echo "(empty)"
    else
        echo "${YELLOW}Cannot read /etc/sudoers${NC}"
    fi
    
    print_sub "PAM Configuration"
    for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        if [[ -f "$pam_file" ]]; then
            echo "=== $pam_file ==="
            grep -vE '^#|^$' "$pam_file" 2>/dev/null || true
            echo ""
        fi
    done
    
    print_sub "Processes Running as Root"
    safe_exec ps -U root -u root u 2>/dev/null | head -40
}

audit_networking() {
    print_header "NETWORKING CHECKS"
    
    print_sub "Active Internet Connections (TCP)"
    if command -v ss &>/dev/null; then
        echo "--- Listening TCP Ports ---"
        ss -tlnp 2>/dev/null
        echo ""
        echo "--- Established TCP Connections ---"
        ss -tnp state established 2>/dev/null
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null
        echo ""
        netstat -tnp 2>/dev/null | grep ESTABLISHED
    else
        cat /proc/net/tcp 2>/dev/null | head -20
    fi
    
    print_sub "Active Internet Connections (UDP)"
    if command -v ss &>/dev/null; then
        ss -ulnp 2>/dev/null
    elif command -v netstat &>/dev/null; then
        netstat -ulnp 2>/dev/null
    fi
    
    print_sub "Network Interfaces"
    if command -v ip &>/dev/null; then
        ip addr show 2>/dev/null
    elif command -v ifconfig &>/dev/null; then
        ifconfig -a 2>/dev/null
    else
        cat /proc/net/dev 2>/dev/null
    fi
    
    print_sub "IP Routing Table"
    if command -v ip &>/dev/null; then
        ip route show 2>/dev/null
    elif command -v route &>/dev/null; then
        route -n 2>/dev/null
    fi
    
    print_sub "DNS Configuration"
    echo "--- /etc/resolv.conf ---"
    if [[ -f /etc/resolv.conf ]]; then
        cat /etc/resolv.conf 2>/dev/null
    fi
    echo ""
    echo "--- /etc/hosts ---"
    if [[ -f /etc/hosts ]]; then
        cat /etc/hosts 2>/dev/null
    fi
    
    print_sub "ARP Table"
    if command -v ip &>/dev/null; then
        ip neigh show 2>/dev/null
    elif command -v arp &>/dev/null; then
        arp -an 2>/dev/null
    fi
    
    print_sub "Connection Summary"
    if command -v ss &>/dev/null; then
        echo "TCP Listening : $(ss -tlnp 2>/dev/null | grep -c LISTEN || echo 0)"
        echo "UDP Listening : $(ss -ulnp 2>/dev/null | wc -l || echo 0)"
        echo "Established   : $(ss -tnp state established 2>/dev/null | wc -l || echo 0)"
        ss -s 2>/dev/null
    fi
    
    print_sub "Firewall Status"
    # UFW (Debian/Ubuntu)
    if command -v ufw &>/dev/null; then
        echo "--- UFW ---"
        ufw status verbose 2>/dev/null || echo "(cannot get status)"
    fi
    
    # Firewalld (RHEL/CentOS/Fedora)
    if command -v firewall-cmd &>/dev/null; then
        echo "--- Firewalld ---"
        echo "State: $(firewall-cmd --state 2>/dev/null || echo 'unknown')"
        firewall-cmd --list-all 2>/dev/null || true
    fi
    
    # iptables (Universal)
    if command -v iptables &>/dev/null; then
        echo "--- iptables (filter table) ---"
        iptables -L -n -v --line-numbers 2>/dev/null | head -60
    fi
    
    # nftables (Newer)
    if command -v nft &>/dev/null; then
        echo "--- nftables ---"
        nft list ruleset 2>/dev/null | head -60
    fi
    
    # CSF (Common on cPanel servers)
    if command -v csf &>/dev/null; then
        echo "--- CSF Firewall ---"
        csf -s 2>/dev/null || true
    fi
}

audit_services() {
    print_header "SERVICES CHECKS"
    
    print_sub "Systemd Running Services"
    if command -v systemctl &>/dev/null; then
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null
    fi
    
    print_sub "Services Enabled at Boot"
    if command -v systemctl &>/dev/null; then
        systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null
    fi
    
    print_sub "Failed Services"
    if command -v systemctl &>/dev/null; then
        systemctl --failed --no-pager 2>/dev/null
    fi
    
    print_sub "Legacy SysV Services (if applicable)"
    if [[ -x /sbin/service ]] || [[ -x /usr/sbin/service ]]; then
        service --status-all 2>/dev/null | grep '\[ + \]' || echo "(no SysV services running)"
    fi
    
    print_sub "Process Tree"
    if command -v pstree &>/dev/null; then
        pstree -paul 2>/dev/null | head -100
    else
        ps -ef --forest 2>/dev/null | head -100
    fi
    
    print_sub "Top CPU Consuming Processes"
    ps aux --sort=-%cpu 2>/dev/null | head -15
    
    print_sub "Top Memory Consuming Processes"
    ps aux --sort=-%mem 2>/dev/null | head -15
    
    print_sub "Socket Statistics"
    if command -v ss &>/dev/null; then
        ss -s 2>/dev/null
    fi
}

audit_security() {
    print_header "SECURITY CHECKS"
    
    print_sub "SSH Server Configuration"
    local ssh_configs="/etc/ssh/sshd_config"
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        ssh_configs="$ssh_configs /etc/ssh/sshd_config.d/*.conf"
    fi
    
    for ssh_conf in $ssh_configs; do
        if [[ -f "$ssh_conf" ]]; then
            echo "=== $ssh_conf ==="
            grep -vE '^#|^$' "$ssh_conf" 2>/dev/null || true
            echo ""
        fi
    done
    
    print_sub "SSH Security Assessment"
    if [[ -f /etc/ssh/sshd_config ]]; then
        local sshd_conf="/etc/ssh/sshd_config"
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            for f in /etc/ssh/sshd_config.d/*.conf; do
                [[ -f "$f" ]] && sshd_conf="$sshd_conf $f"
            done
        fi
        
        echo "PermitRootLogin         : $(grep -ih "^PermitRootLogin" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: prohibit-password)")"
        echo "PasswordAuthentication  : $(grep -ih "^PasswordAuthentication" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: yes)")"
        echo "PermitEmptyPasswords    : $(grep -ih "^PermitEmptyPasswords" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: no)")"
        echo "X11Forwarding           : $(grep -ih "^X11Forwarding" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: no)")"
        echo "MaxAuthTries            : $(grep -ih "^MaxAuthTries" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: 6)")"
        echo "Protocol                : $(grep -ih "^Protocol" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: 2)")"
        echo "AllowUsers              : $(grep -ih "^AllowUsers" $sshd_conf 2>/dev/null | tail -1 | cut -d: -f2- || echo "Not set (all users allowed)")"
        echo "DenyUsers               : $(grep -ih "^DenyUsers" $sshd_conf 2>/dev/null | tail -1 | cut -d: -f2- || echo "Not set")"
        echo "UseDNS                  : $(grep -ih "^UseDNS" $sshd_conf 2>/dev/null | tail -1 | awk '{print $2}' || echo "Not set (default: yes)")"
    fi
    
    print_sub "World Writable Files (Sample)"
    echo "Scanning... (timeout: 30s)"
    safe_find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
    
    print_sub "World Writable Directories"
    safe_find / -xdev -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -30
    
    print_sub "SUID Files (Potential Privilege Escalation)"
    safe_find / -xdev -type f -perm -4000 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
    
    print_sub "SGID Files"
    safe_find / -xdev -type f -perm -2000 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
    
    print_sub "Files with No Owner/Group"
    safe_find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null | head -30
    
    print_sub "Sysctl Security Parameters"
    local -a sysctl_params=(
        "kernel.randomize_va_space"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.conf.default.accept_redirects"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.all.rp_filter"
        "net.ipv4.conf.default.rp_filter"
        "net.ipv4.icmp_echo_ignore_broadcasts"
        "net.ipv4.conf.all.accept_source_route"
        "net.ipv4.conf.default.accept_source_route"
        "net.ipv4.tcp_syncookies"
        "net.ipv4.conf.all.log_martians"
        "kernel.dmesg_restrict"
        "kernel.kptr_restrict"
        "fs.suid_dumpable"
        "net.core.somaxconn"
        "net.ipv4.tcp_max_syn_backlog"
    )
    
    for param in "${sysctl_params[@]}"; do
        local value
        value=$(sysctl -n "$param" 2>/dev/null) && echo "$param = $value" || echo "$param = (not available)"
    done
    
    print_sub "Dangerous Dotfiles"
    safe_find /home /root /tmp /var/tmp -maxdepth 3 \
        \( -name ".rhosts" -o -name ".netrc" -o -name ".forward" \) -type f 2>/dev/null
    
    print_sub "Sensitive Directory Permissions"
    echo "/tmp  : $(ls -ld /tmp 2>/dev/null | awk '{print $1, $3, $4}')"
    echo "/var/tmp: $(ls -ld /var/tmp 2>/dev/null | awk '{print $1, $3, $4}')"
    echo "/dev/shm: $(ls -ld /dev/shm 2>/dev/null | awk '{print $1, $3, $4}')"
    
    print_sub "Missing Sticky Bit on World-Writable Directories"
    safe_find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20
    
    print_sub "Password Hashing Algorithm"
    if [[ -r /etc/shadow ]]; then
        local hash_type
        hash_type=$(head -1 /etc/shadow 2>/dev/null | cut -d: -f2 | cut -c1-3)
        case "$hash_type" in
            '$1$') echo "${RED}WARNING: Using MD5 (weak!)${NC}" ;;
            '$5$') echo "${YELLOW}OK: Using SHA-256 (could be stronger)${NC}" ;;
            '$6$') echo "${GREEN}OK: Using SHA-512 (recommended)${NC}" ;;
            '$y$') echo "${GREEN}OK: Using yescrypt (modern)${NC}" ;;
            '$2'$'') echo "${YELLOW}Using bcrypt${NC}" ;;
            *) echo "Unknown/Custom: $hash_type" ;;
        esac
    else
        echo "${YELLOW}Cannot read /etc/shadow (root required)${NC}"
    fi
    
    print_sub "SSH Authorized Keys"
    echo "--- Root ---"
    if [[ -f /root/.ssh/authorized_keys ]]; then
        cat /root/.ssh/authorized_keys 2>/dev/null || echo "(not readable)"
        echo ""
        echo "Key count: $(wc -l < /root/.ssh/authorized_keys 2>/dev/null || echo 0)"
    else
        echo "(no authorized_keys file)"
    fi
    
    echo ""
    echo "--- Users ---"
    find /home -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
        echo "=== $keyfile ==="
        cat "$keyfile" 2>/dev/null
        echo "Key count: $(wc -l < "$keyfile" 2>/dev/null || echo 0)"
        echo ""
    done
}

audit_webserver() {
    print_header "WEBSERVER CHECKS"
    
    local apache_service nginx_service apache_log_path
    
    apache_service=$(get_webserver_service_name "apache")
    nginx_service=$(get_webserver_service_name "nginx")
    apache_log_path=$(get_webserver_log_path "apache")
    
    # Check Apache/httpd
    print_sub "Apache/httpd Status"
    if systemctl is-active --quiet "$apache_service" 2>/dev/null || pgrep -x "$apache_service" &>/dev/null; then
        echo "${GREEN}[RUNNING] Service: $apache_service${NC}"
        echo "Log path: $apache_log_path"
        
        if [[ -d "$apache_log_path" ]]; then
            echo ""
            echo "--- Recent Access Logs (last 30 lines) ---"
            for logfile in "$apache_log_path"/access*.log; do
                if [[ -f "$logfile" ]]; then
                    echo ">>> $logfile"
                    tail -n 30 "$logfile" 2>/dev/null
                fi
            done
            
            echo ""
            echo "--- Recent Error Logs (last 30 lines) ---"
            for logfile in "$apache_log_path"/error*.log; do
                if [[ -f "$logfile" ]]; then
                    echo ">>> $logfile"
                    tail -n 30 "$logfile" 2>/dev/null
                fi
            done
        fi
    else
        echo "${YELLOW}[NOT RUNNING] $apache_service${NC}"
    fi
    
    # Check Nginx
    print_sub "Nginx Status"
    if systemctl is-active --quiet nginx 2>/dev/null || pgrep -x nginx &>/dev/null; then
        echo "${GREEN}[RUNNING] Service: nginx${NC}"
        
        local nginx_log="/var/log/nginx"
        if [[ -d "$nginx_log" ]]; then
            echo ""
            echo "--- Recent Access Logs (last 30 lines) ---"
            for logfile in "$nginx_log"/access*.log; do
                if [[ -f "$logfile" ]]; then
                    echo ">>> $logfile"
                    tail -n 30 "$logfile" 2>/dev/null
                fi
            done
            
            echo ""
            echo "--- Recent Error Logs (last 30 lines) ---"
            for logfile in "$nginx_log"/error*.log; do
                if [[ -f "$logfile" ]]; then
                    echo ">>> $logfile"
                    tail -n 30 "$logfile" 2>/dev/null
                fi
            done
        fi
    else
        echo "${YELLOW}[NOT RUNNING] nginx${NC}"
    fi
    
    # Check other webservers
    print_sub "Other Webservers"
    local -a other_servers=(lighttpd caddy tomcat httpd apache2)
    for server in "${other_servers[@]}"; do
        # Skip if already checked
        [[ "$server" == "$apache_service" ]] && continue
        [[ "$server" == "nginx" ]] && continue
        
        if systemctl is-active --quiet "$server" 2>/dev/null || pgrep -x "$server" &>/dev/null; then
            echo "${GREEN}[RUNNING] $server${NC}"
            systemctl status "$server" --no-pager 2>/dev/null | head -15
        fi
    done
    
    # Document roots
    print_sub "Web Document Roots"
    local -a doc_roots=(/var/www/html /var/www /srv/www /usr/share/nginx/html /var/www/vhosts /srv/http)
    for docroot in "${doc_roots[@]}"; do
        if [[ -d "$docroot" ]]; then
            echo "=== $docroot ==="
            ls -la "$docroot" 2>/dev/null | head -20
            echo ""
        fi
    done
}

audit_suspicious_files() {
    print_header "SUSPICIOUS FILE CHECKS"
    
    print_sub "PHP Webshell Detection"
    local -a web_dirs=(/var/www /srv/www /usr/share/nginx/html /home /srv/http /opt)
    local -a php_patterns=("eval\(" "base64_decode\(" "shell_exec\(" "system\(" "exec\(" "passthru\(" "popen\(" "proc_open\(" "pcntl_exec\(" "assert\(" "preg_replace.*\/e" "create_function" "call_user_func")
    
    for webdir in "${web_dirs[@]}"; do
        if [[ -d "$webdir" ]]; then
            for pattern in "${php_patterns[@]}"; do
                find "$webdir" -type f -name "*.php" -exec grep -l "$pattern" {} \; 2>/dev/null | head -20
            done
        fi
    done | sort -u | head -50
    
    print_sub "Suspicious .bat Files (Unusual on Linux)"
    safe_find / -type f -name "*.bat" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20
    
    print_sub "Suspicious Shell Scripts"
    local -a shell_patterns=("curl " "wget " "nc " "netcat " "bash -i" "sh -i" "/dev/tcp" "mkfifo" "mknod" "socat TCP" "openssl s_client")
    
    for pattern in "${shell_patterns[@]}"; do
        find /tmp /var/tmp /dev/shm /home /root /opt -type f -name "*.sh" -exec grep -l "$pattern" {} \; 2>/dev/null
    done | sort -u | head -30
    
    print_sub "Recently Modified Files in Sensitive Directories (7 days)"
    local -a sensitive_dirs=(/etc /usr/bin /usr/sbin /bin /sbin)
    for dir in "${sensitive_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            echo "=== $dir ==="
            safe_find "$dir" -type f -mtime -7 2>/dev/null | head -15
            echo ""
        fi
    done
    
    print_sub "Hidden Files in Temp Directories"
    safe_find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null | head -30
    
    print_sub "Executable Files in Temp Directories"
    safe_find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -30
    
    print_sub "Reverse Shell Indicators"
    local -a reverse_patterns=("bash -i" "sh -i" "/dev/tcp" "nc -e" "ncat -e" "socat TCP" "mkfifo" "openssl s_client" "python -c.*socket")
    for pattern in "${reverse_patterns[@]}"; do
        grep -r "$pattern" /tmp /var/tmp /dev/shm 2>/dev/null
    done | head -30
    
    print_sub "Large Files in Temp Directories (>10MB)"
    safe_find /tmp /var/tmp /dev/shm -type f -size +10M -exec ls -lh {} \; 2>/dev/null | head -20
}

audit_mining() {
    print_header "CRYPTOMINING CHECKS"
    
    local -a mining_patterns=("xmrig" "minerd" "cryptonight" "cpuminer" "coinhive" "cryptominer" "ethminer" "claymore" "phoenixminer" "t-rex" "nbminer" "gminer" "lolminer" "hiveon" "xmrig-proxy" "stratumproxy" "xmr-stak" "nanominer" "teamredminer" "tbminer")
    
    print_sub "Mining Processes"
    local mining_procs
    mining_procs=$(ps aux 2>/dev/null | grep -iE "$(IFS='|'; echo "${mining_patterns[*]}")" | grep -v grep)
    if [[ -n "$mining_procs" ]]; then
        echo "${RED}SUSPICIOUS: Mining processes found!${NC}"
        echo "$mining_procs"
    else
        echo "(no mining processes detected)"
    fi
    
    print_sub "Mining Services"
    if command -v systemctl &>/dev/null; then
        local mining_services
        mining_services=$(systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -iE "$(IFS='|'; echo "${mining_patterns[*]}")")
        if [[ -n "$mining_services" ]]; then
            echo "${RED}SUSPICIOUS: Mining services found!${NC}"
            echo "$mining_services"
        else
            echo "(no mining services detected)"
        fi
    fi
    
    print_sub "Mining-related Files"
    local -a mining_filenames=("*xmrig*" "*minerd*" "*cryptonight*" "*cpuminer*" "*xmr-stak*")
    for pattern in "${mining_filenames[@]}"; do
        safe_find / -type f -name "$pattern" ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null
    done | head -30
    
    print_sub "Connections to Common Mining Ports"
    local -a mining_ports=("4444" "3333" "5555" "14444" "45560" "45700" "8888" "7777" "9999" "3357")
    if command -v ss &>/dev/null; then
        for port in "${mining_ports[@]}"; do
            ss -tnp 2>/dev/null | grep ":$port " && echo "${RED}Connection to mining port $port detected!${NC}"
        done
        echo "(scan complete)"
    fi
    
    print_sub "High CPU Processes (Potential Mining)"
    ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>70 {print "SUSPICIOUS (CPU " $3 "%): " $11}' | head -10
    
    print_sub "Docker Containers for Mining"
    if command -v docker &>/dev/null; then
        docker ps --format "{{.Names}}: {{.Image}}" 2>/dev/null | grep -iE "$(IFS='|'; echo "${mining_patterns[*]}")" && echo "${RED}Mining container detected!${NC}" || echo "(no mining containers)"
    fi
}

audit_containers() {
    print_header "CONTAINER & VIRTUALIZATION CHECKS"
    
    # Docker
    print_sub "Docker"
    if command -v docker &>/dev/null; then
        echo "--- Version ---"
        docker version --format '{{.Server.Version}}' 2>/dev/null || docker version 2>/dev/null | head -10
        
        echo ""
        echo "--- Running Containers ---"
        docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
        
        echo ""
        echo "--- All Containers ---"
        docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null | head -30
        
        echo ""
        echo "--- Images ---"
        docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null | head -20
        
        echo ""
        echo "--- Networks ---"
        docker network ls 2>/dev/null
        
        echo ""
        echo "--- Volumes ---"
        docker volume ls 2>/dev/null | head -20
        
        echo ""
        echo "--- Privileged Containers ---"
        docker ps --format '{{.Names}}' 2>/dev/null | while read -r container; do
            if docker inspect "$container" 2>/dev/null | grep -q '"Privileged": true'; then
                echo "${RED}WARNING: $container is running privileged!${NC}"
            fi
        done
    else
        echo "(Docker not installed)"
    fi
    
    # Podman
    print_sub "Podman"
    if command -v podman &>/dev/null; then
        podman ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null
        echo ""
        podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null | head -20
    else
        echo "(Podman not installed)"
    fi
    
    # LXC/LXD
    print_sub "LXC/LXD"
    if command -v lxc &>/dev/null; then
        lxc list 2>/dev/null || lxc-ls -fancy 2>/dev/null
    else
        echo "(LXC/LXD not installed)"
    fi
    
    # KVM/QEMU
    print_sub "KVM/QEMU Virtual Machines"
    if command -v virsh &>/dev/null; then
        virsh list --all 2>/dev/null
    elif command -v qemu-system-x86_64 &>/dev/null; then
        echo "QEMU installed but libvirt not available"
        ps aux 2>/dev/null | grep -i qemu | grep -v grep
    else
        echo "(KVM/QEMU not installed or not accessible)"
    fi
}

audit_additional_security() {
    print_header "ADDITIONAL SECURITY CHECKS"
    
    print_sub "Kernel Modules (Suspicious)"
    local suspicious_modules
    suspicious_modules=$(lsmod 2>/dev/null | grep -iE "hide|rootkit|kit|invisible|cloak")
    if [[ -n "$suspicious_modules" ]]; then
        echo "${RED}SUSPICIOUS: $suspicious_modules${NC}"
    else
        echo "(no suspicious modules)"
    fi
    
    print_sub "All Loaded Kernel Modules"
    lsmod 2>/dev/null | head -40
    
    print_sub "LD_PRELOAD Check"
    echo "Current LD_PRELOAD: ${LD_PRELOAD:-Not set}"
    if [[ -f /etc/ld.so.preload ]]; then
        echo "${RED}WARNING: /etc/ld.so.preload exists!${NC}"
        cat /etc/ld.so.preload 2>/dev/null
    else
        echo "/etc/ld.so.preload: (not found - good)"
    fi
    
    print_sub "Account Lockout Status"
    if command -v faillock &>/dev/null; then
        echo "--- Root ---"
        faillock --user root 2>/dev/null || echo "(no lockouts)"
        echo ""
        echo "--- All Users ---"
        faillock --all 2>/dev/null | head -30 || echo "(no lockouts)"
    elif [[ -f /var/log/btmp ]]; then
        echo "--- Failed logins (lastb) ---"
        lastb 2>/dev/null | head -30
    fi
    
    print_sub "USB Device History"
    if [[ -f /var/log/dmesg ]]; then
        grep -i "usb\|sd[a-z]" /var/log/dmesg 2>/dev/null | tail -20
    else
        dmesg 2>/dev/null | grep -i "usb" | tail -20 || echo "(cannot read dmesg)"
    fi
    
    print_sub "Recently Installed Packages"
    local pkg_manager
    pkg_manager=$(get_package_manager)
    
    case "$pkg_manager" in
        apt)
            if [[ -f /var/log/dpkg.log ]]; then
                grep " install " /var/log/dpkg.log 2>/dev/null | tail -30
            fi
            ;;
        dnf|yum)
            rpm -qa --last 2>/dev/null | head -30
            ;;
        pacman)
            pacman -Qe 2>/dev/null | head -30
            ;;
        zypper)
            zypper search -i --sort-by-name 2>/dev/null | head -30
            ;;
        apk)
            apk info 2>/dev/null | head -30
            ;;
        *)
            echo "(unknown package manager)"
            ;;
    esac
    
    print_sub "Security Updates Available"
    case "$pkg_manager" in
        apt)
            apt list --upgradable 2>/dev/null | head -20
            ;;
        dnf)
            dnf check-update --quiet 2>/dev/null | head -20
            ;;
        yum)
            yum check-update 2>/dev/null | head -20
            ;;
        pacman)
            pacman -Qu 2>/dev/null | head -20
            ;;
        zypper)
            zypper list-updates 2>/dev/null | head -20
            ;;
        apk)
            apk upgrade --simulate 2>/dev/null | head -20
            ;;
        *)
            echo "(cannot check updates)"
            ;;
    esac
    
    print_sub "SSH Host Keys"
    echo "--- Fingerprint Check ---"
    for keyfile in /etc/ssh/ssh_host_*_key.pub; do
        if [[ -f "$keyfile" ]]; then
            echo "$keyfile:"
            ssh-keygen -l -f "$keyfile" 2>/dev/null
        fi
    done
    
    print_sub "AT Jobs (Scheduled Tasks)"
    if command -v atq &>/dev/null; then
        atq 2>/dev/null || echo "(no at jobs)"
    else
        echo "(at not installed)"
    fi
    
    print_sub "Systemd User Services"
    if command -v systemctl &>/dev/null; then
        for user_dir in /home/*/.config/systemd/user /root/.config/systemd/user; do
            if [[ -d "$user_dir" ]]; then
                echo "=== $user_dir ==="
                ls -la "$user_dir"/*.service 2>/dev/null | head -20
            fi
        done
    fi
}

# ==================== MAIN AUDIT FUNCTION ====================
perform_audit() {
    local separator="═══════════════════════════════════════════════════════════════════════════════"
    
    echo "$separator"
    echo "  LINUX SECURITY AUDIT REPORT"
    echo "  Generated : $(date)"
    echo "  Host      : $HOSTNAME_VAR"
    echo "  Version   : $SCRIPT_VERSION"
    echo "$separator"
    
    local distro_info
    distro_info=$(detect_distro)
    local distro_name version distro_family
    distro_name=$(echo "$distro_info" | cut -d'|' -f1)
    version=$(echo "$distro_info" | cut -d'|' -f2)
    distro_family=$(echo "$distro_info" | cut -d'|' -f3)
    
    echo ""
    echo "Distribution : $distro_name"
    echo "Version      : $version"
    echo "Family       : $distro_family"
    echo "Arch         : $(uname -m 2>/dev/null || echo 'unknown')"
    echo "Kernel       : $(uname -r 2>/dev/null || echo 'unknown')"
    
    audit_system_information
    audit_users_and_groups
    audit_networking
    audit_services
    audit_security
    audit_webserver
    audit_suspicious_files
    audit_mining
    audit_containers
    audit_additional_security
    
    echo ""
    echo "$separator"
    echo "  AUDIT COMPLETED"
    echo "  End Time : $(date)"
    echo "  Duration : $SECONDS seconds"
    echo "$separator"
}

# ==================== SCRIPT ENTRY POINT ====================
main() {
    tput clear 2>/dev/null || clear 2>/dev/null || true
    
    echo "  ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗     ██╗   ██╗██████╗  "
    echo "  ██║     ██║████╗  ██║██║   ██╗╚██╗██╔╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║     ██║   ██║██╔══██╗ "
    echo "  ██║     ██║██╔██╗ ██║██║   ██╗ ╚███╔╝ ███████║██║   ██║██║  ██║██║   ██║   ██║     ██║   ██║██████╔╝ "
    echo "  ██║     ██║██║╚██╗██║██║   ██╗ ██╔██╗ ██╔══██║██║   ██║██║  ██║██║   ██║   ██║     ██║   ██║██╔══██╗ "
    echo "  ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗██║  ██║╚██████╔╝██████╔╝██║   ██║   ███████╗╚██████╔╝██║  ██║ "
    echo "  ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ "
    echo ""
    echo -e "${BOLD}Gagaltotal666 | Linux Security Audit Script v$SCRIPT_VERSION${NC}"
    echo ""
    
    echo -e "${CYAN}Dukungan Multi-Distro:${NC}"
    echo "  • Debian/Ubuntu/Mint/Kali/Parrot (Debian Family)"
    echo "  • RHEL/CentOS/Rocky/Alma/Fedora/Oracle Linux (RHEL Family)"
    echo "  • Arch Linux/Manjaro/EndeavourOS (Arch Family)"
    echo "  • openSUSE/SLES (SUSE Family)"
    echo "  • Alpine Linux"
    echo "  • Gentoo, Void, Slackware, dan lainnya"
    echo ""
    echo -e "${YELLOW}Catatan: Beberapa cek membutuhkan akses root untuk hasil lengkap${NC}"
    echo ""
    
    local distro_info
    distro_info=$(detect_distro)
    local distro_name distro_family
    distro_name=$(echo "$distro_info" | cut -d'|' -f1)
    distro_family=$(echo "$distro_info" | cut -d'|' -f3)
    
    echo -e "Distro terdeteksi: ${GREEN}$distro_name${NC}"
    echo -e "Keluarga          : ${GREEN}$distro_family${NC}"
    echo ""
    
    if [[ $EUID -eq 0 ]]; then
        echo -e "${GREEN}[✓] Berjalan sebagai root - Akses penuh${NC}"
    else
        echo -e "${YELLOW}[!] Tidak berjalan sebagai root - Beberapa cek mungkin terbatas${NC}"
    fi
    echo ""
    
    read -p "Tekan Enter untuk memulai audit... " -r
    
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        echo -e "${RED}Error: Tidak bisa membuat direktori $OUTPUT_DIR${NC}" >&2
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}Output akan disimpan ke: $OUTPUT_FILE${NC}"
    echo ""
    
    SECONDS=0
    
    {
        perform_audit
    } 2>&1 | tee >(sed 's/\x1b\[[0-9;]*m//g' > "$output_file")
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✓ Audit selesai!${NC}"
    echo -e "${GREEN}  Hasil disimpan di: $output_file${NC}"
    echo -e "${GREEN}  Waktu eksekusi   : $SECONDS detik${NC}"
    echo -e "${GREEN}  Selesai pada     : $(date)${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    
    if [[ -f "$LOG_FILE" ]] && [[ -s "$LOG_FILE" ]]; then
        echo ""
        echo -e "${YELLOW}[!] Ada error selama audit. Detail: $LOG_FILE${NC}"
        echo -e "${YELLOW}    Jumlah error: $(wc -l < "$LOG_FILE")${NC}"
    fi
}

main "$@"