#!/bin/bash
# Linux Audit Script - Gagaltotal666

tput clear

# Trap Ctrl+C
trap ctrl_c INT
function ctrl_c() {
    echo "** Anda menekan Ctrl+C... Keluar"
    exit 0
}

echo "  ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗     ██╗   ██╗██████╗  "
echo "  ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║     ██║   ██║██╔══██╗ "
echo "  ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ ███████║██║   ██║██║  ██║██║   ██║   ██║     ██║   ██║██████╔╝ "
echo "  ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ ██╔══██║██║   ██║██║  ██║██║   ██║   ██║     ██║   ██║██╔══██╗ "
echo "  ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗██║  ██║╚██████╔╝██████╔╝██║   ██║   ███████╗╚██████╔╝██║  ██║ "
echo "  ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ "

echo
echo "Gagaltotal666 | Selamat datang di audit keamanan mesin Linux Anda"
echo "Catatan: diuji pada Distro Linux Debian/Ubuntu"
echo
sleep 2

# Buat folder output otomatis
timestamp=$(date +"%Y%m%d-%H%M%S")
hostname=$(hostname)
output_dir="LinuxAudit-${hostname}-${timestamp}"
mkdir -p "$output_dir"
output_file="$output_dir/LinuxAudit.txt"

echo "Output akan disimpan ke: $output_file"
sleep 2

# ========== FUNCTION AUDIT ==========
perform_audit() {

    Linux_System_Information_checks(){
        printf "\n[+] Linux Kernel Information\n"
        uname -a

        printf "\n[+] Linux Distribution Information\n"
        lsb_release -a 2>/dev/null || cat /etc/*release

        printf "\n[+] $HOSTNAME Uptime Information\n"
        uptime

        printf "\n[+] Disk Space\n"
        df -h

        printf "\n[+] Memory\n"
        free -h

        printf "\n[+] TCP wrappers\n"
        cat /etc/hosts.allow
        cat /etc/hosts.deny
        
        printf "\n[+] Cron jobs\n"
        printf "\n[+] Crontab User\n"
        crontab -l 2>/dev/null
        printf "\n[+] Crontab System wide\n"
        ls -la /etc/cron*
        
        printf "\n[+] Last reboots\n"
        last reboot | head
    }

    Users_and_Groups_Checks(){
        printf "\n[+] Current User and ID information\n"
        whoami && id
        printf "\n[+] Logged In Users\n"
        w
        printf "\n[+] Users and Shells\n"
        awk -F: '{print $1, $7}' /etc/passwd
        printf "\n[+] Services run by Root\n"
        ps -U root -u root u
    }

    Networking_Checks(){
        printf "\n[+] Active Internet Connections and Open Ports\n"
        ss -tulnp
        printf "\n[+] Network Interfaces\n"
        ip addr show
        printf "\n[+] IP Routing Table\n"
        ip route
    }

    Services_Checks(){
        printf "\n[+] Running Services\n"
        service --status-all 2>/dev/null | grep "+"
        printf "\n[+] Processes (Tree)\n"
        ps -ef --forest
    }

    Security_checks(){
        printf "\n[+] SSH Config\n"
        grep -v '^#' /etc/ssh/sshd_config | grep -v '^$'

        printf "\n[+] UID 0 users other than root\n"
        awk -F: '($3 == 0 && $1 != "root"){print}' /etc/passwd

        printf "\n[+] World Writable Files\n"
        find / -xdev -type f -perm -0002 2>/dev/null | head -n 50

        printf "\n[+] SUID/SGID Files\n"
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -n 50

        printf "\n[+] Sysctl security params\n"
        sysctl kernel.randomize_va_space
        sysctl net.ipv4.conf.all.accept_redirects
        sysctl net.ipv4.conf.all.rp_filter
        
        printf "\n[+] Dangerous dotfiles\n"
        find /home /root -maxdepth 2 \( -name .rhosts -o -name .netrc -o -name .forward \) 2>/dev/null
    }

    Webserver_Checks(){
        printf "\n[+] Webserver Logs\n"
        if systemctl is-active --quiet apache2; then
            echo "Apache is running"
            tail -n 50 /var/log/apache2/access.log 2>/dev/null
            tail -n 50 /var/log/apache2/error.log 2>/dev/null
        fi
        if systemctl is-active --quiet nginx; then
            echo "Nginx is running"
            tail -n 50 /var/log/nginx/access.log 2>/dev/null
            tail -n 50 /var/log/nginx/error.log 2>/dev/null
        fi
    }

    Suspicious_Shell_Checks(){
        printf "\n[+] Searching for suspicious PHP shells\n"
        grep -R --include="*.php" -E "eval\(|base64_decode\(|shell_exec\(|system\(|exec\(" /var/www/ 2>/dev/null | head -n 50

        printf "\n[+] Searching for .bat files\n"
        find / -type f -name "*.bat" 2>/dev/null | head -n 50

        printf "\n[+] Searching for suspicious .sh scripts\n"
        find / -type f -name "*.sh" 2>/dev/null | xargs grep -EH "curl|wget|nc|bash|sh" 2>/dev/null | head -n 50

        printf "\n[+] Check for Root Access via .ssh/authorized_keys\n"
        find /root/.ssh /home/*/.ssh -type f -name "authorized_keys" 2>/dev/null | xargs -r cat
    }

    Mining_Checks(){
        printf "\n[+] Checking for suspicious mining processes/services\n"
        ps aux | egrep "xmrig|minerd|cryptonight|cpuminer|coinhive|cryptominer" | grep -v egrep

        printf "\n[+] Checking for suspicious services related to mining\n"
        systemctl list-units --type=service | egrep "xmrig|minerd|cryptonight|cpuminer|miner"
    }

    # Run all checks
    Linux_System_Information_checks
    Users_and_Groups_Checks
    Networking_Checks
    Services_Checks
    Security_checks
    Webserver_Checks
    Suspicious_Shell_Checks
    Mining_Checks
}

# Jalankan audit dan simpan ke file
perform_audit | tee "$output_file"

echo
echo "Audit selesai. Hasil disimpan di $output_file"
echo "Dieksekusi pada: $(date)"