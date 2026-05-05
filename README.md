# Linux Security Audit Script v2.0

## Deskripsi

**Linux Security Audit Script (linux-audit-tot.sh)** adalah skrip Bash komprehensif untuk melakukan audit keamanan sistem Linux. Skrip ini dirancang untuk mengumpulkan informasi keamanan lengkap dari sistem Linux dan menghasilkan laporan detail dalam satu file output.

Skrip mendukung **berbagai distribusi Linux** termasuk:
- **Debian/Ubuntu** (dan derivatnya seperti Linux Mint, Kali, Parrot)
- **RHEL/CentOS/Fedora** (dan Rocky, AlmaLinux, Oracle Linux)
- **Arch Linux** (dan Manjaro, EndeavourOS)
- **SUSE** (OpenSUSE Leap/Tumbleweed, SLES)
- **Alpine Linux**
- **Gentoo**
- **Slackware**
- Dan distribusi lainnya

---

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/linux-audit-lur/refs/heads/main/Screenshot%20from%202026-05-05%2012-54-34.png)

## Fitur Utama

### 1. **System Information Audit**
   - Kernel dan informasi distro
   - Uptime dan load average
   - Informasi CPU (cores, model, MHz)
   - Penggunaan disk dan memory
   - Swap configuration
   - Last reboot history

### 2. **Users & Groups Security**
   - Informasi user yang sedang login
   - Login history dan failed login attempts
   - Users dengan login shells
   - Detection user dengan UID 0 (root equivalent)
   - Password policy checks
   - Sudoers configuration
   - PAM configuration
   - TCP wrappers (/etc/hosts.allow, /etc/hosts.deny)

### 3. **Scheduled Tasks**
   - User crontabs
   - System crontab
   - Cron directories (/etc/cron.d, /etc/cron.daily, dll)
   - Systemd timers

### 4. **Filesystem Security**
   - SUID/SGID files
   - World-writable directories
   - World-writable files
   - Files dengan sticky bit
   - Unowned/ungrouped files
   - Permission issues dan security risks

### 5. **Network Security**
   - Network interfaces dan IP addresses
   - Routing table
   - Listening ports dan services
   - Network connections
   - DNS configuration
   - Firewall status (iptables/firewalld)
   - IPv4/IPv6 forwarding status

### 6. **Package Management**
   - List installed packages
   - Available updates
   - Repository configuration
   - Package manager specific info

### 7. **Services & Processes**
   - Running services status
   - Process listing
   - Service dependencies
   - Systemd unit files

### 8. **Configuration Files Audit**
   - SSH configuration
   - Sysctl parameters
   - Kernel modules
   - System limits
   - Security-related configurations

### 9. **Log Files Analysis**
   - Auth logs (authentication attempts)
   - System logs
   - Security logs
   - Error tracking

### 10. **Security Tools Detection**
   - Antivirus/malware detection tools
   - Intrusion detection systems
   - Host-based firewalls
   - SELinux/AppArmor status

---

## Cara Penggunaan

### Instalasi & Persiapan

1. Buka terminal
2. Ubah permission skrip:
   ```bash
   chmod +x linux-audit-tot.sh
   ```

3. Jalankan skrip:
   ```bash
   ./linux-audit-tot.sh
   ```
   atau jika permission tidak berhasil diubah:
   ```bash
   bash linux-audit-tot.sh
   ```

### Keluaran

Skrip akan membuat direktori baru dengan format:
```
LinuxAudit-{hostname}-{timestamp}/
├── LinuxAudit.txt        # Main audit report
└── audit_errors.log      # Error log (jika ada)
```

Contoh: `LinuxAudit-myserver-20250510-143022/`

---

## Fitur Teknis

### Error Handling
- **Strict mode** dengan safe execution untuk setiap command
- **Timeout protection** untuk operasi yang berpotensi hang (30 detik)
- **Error logging** ke file terpisah tanpa menghentikan script
- **Safe command execution** dengan validation sebelum run

### Multi-Distro Support
- Automatic distro detection via `/etc/os-release`
- Fallback methods untuk sistem lama
- Distro-specific command mapping (package managers, log paths, service names)
- Compatible dengan berbagai package managers (apt, yum, dnf, pacman, zypper, apk)

### Output Formatting
- Color-coded output (dengan fallback untuk terminal tanpa color support)
- Organized sections dengan headers
- Tidy error handling tanpa crash
- Comprehensive error logging

### Environment Detection
- Detects interactive vs non-interactive terminals
- Dynamic color support based on terminal capabilities
- Graceful degradation untuk limited environments

---

## Requirements

- **Bash 4.0+**
- **Common Linux utilities**: find, grep, awk, sed, ls, cat, etc.
- **Root or sudo access** (untuk informasi keamanan lengkap)
  - Beberapa informasi memerlukan root privileges
  - Script berjalan partial jika non-root (dengan warnings)

---

## Security Notes

- Skrip bersifat **read-only** - tidak memodifikasi sistem
- Hasil audit dapat berisi informasi sensitif - simpan dengan aman
- Output file harus dibaca dengan hati-hati
- Gunakan untuk audit keamanan sistem sendiri saja

---

## Version Info

**Version**: 2.0  
**Author**: Gagaltotal666  
**Multi-Distro Support**: Yes  
**Last Updated**: 2025

---

## Tips

- Jalankan dengan `sudo` untuk hasil audit yang paling lengkap:
  ```bash
  sudo ./linux-audit-tot.sh
  ```
- Output dapat disimpan untuk dokumentasi keamanan
- Gunakan untuk security baseline dan compliance checking
- Cocok untuk system hardening verification

---

## Screenshot

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/linux-audit-lur/refs/heads/main/Screenshot%20from%202025-09-10%2000-29-28.png)
