#!/bin/bash

# Linux_EnumPE - Privilege Escalation Enumeration Tool
# Created by Hernan Rodriguez

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPORT_DIR="Linux_EnumPE_Reports"
CURRENT_USER=$(whoami)
CURRENT_DATE=$(date +"%Y-%m-%d_%H-%M-%S")
KERNEL_VERSION=$(uname -r 2>/dev/null)

PROGRAMMING_LANGS=(
    "perl" "gcc" "g++" "python" "python3" "php" "cc" "go" 
    "node" "npm" "ruby" "java" "rustc" "cargo"
)

PASSWORD_FILES=(
    "*.php" "*.txt" "*.c" "*.db" "*.rb" "*.py" "*.html" "*.js" "*.json" "*.xml" 
    "*.yml" "*.yaml" "*.conf" "*.config" "*db*" "*.db" "*database*" "*password*"
    "*credential*" "wp-config.php" "configuration.php" "config.php" "settings.php"
    "local.xml" "parameters.yml" ".env" ".credentials"
)

SSH_KEYS=(
    "~/.ssh/authorized_keys" "~/.ssh/identity.pub" "~/.ssh/identity" "~/.ssh/id_rsa.pub"
    "~/.ssh/id_rsa" "~/.ssh/id_dsa.pub" "~/.ssh/id_dsa" "~/.ssh/id_ecdsa" "~/.ssh/id_ed25519"
    "/etc/ssh/ssh_host_dsa_key.pub" "/etc/ssh/ssh_host_dsa_key" "/etc/ssh/ssh_host_rsa_key.pub"
    "/etc/ssh/ssh_host_rsa_key" "/etc/ssh/ssh_host_key.pub" "/etc/ssh/ssh_host_key"
)

INTERESTING_DIRS=(
    "/var/log" "/var/mail" "/var/spool" "/var/spool/lpd" "/var/lib/pgsql" "/var/lib/dhcp3/"
    "/var/log/postgresql/" "/var/log/proftpd/" "/var/log/samba/" "/var/www" "/opt" "/tmp" "/home" "/root"
)

LOG_FILES=(
    "/etc/httpd/logs/access_log" "/etc/httpd/logs/access.log" "/etc/httpd/logs/error_log" "/etc/httpd/logs/error.log"
    "/var/log/apache2/access_log" "/var/log/apache2/access.log" "/var/log/apache2/error_log" "/var/log/apache2/error.log"
    "/var/log/apache/access_log" "/var/log/apache/access.log" "/var/log/auth.log" "/var/log/chttp.log"
    "/var/log/cups/error_log" "/var/log/dpkg.log" "/var/log/faillog" "/var/log/httpd/access_log"
    "/var/log/httpd/access.log" "/var/log/httpd/error_log" "/var/log/httpd/error.log" "/var/log/lastlog"
    "/var/log/lighttpd/access.log" "/var/log/lighttpd/error.log" "/var/log/lighttpd/lighttpd.access.log"
    "/var/log/lighttpd/lighttpd.error.log" "/var/log/messages" "/var/log/secure" "/var/log/syslog"
    "/var/log/wtmp" "/var/log/xferlog" "/var/log/yum.log" "/var/run/utmp" "/var/webmin/miniserv.log"
    "/var/www/logs/access_log" "/var/www/logs/access.log"
)

CLOUD_METADATA_ENDPOINTS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/user-data/"
    "http://169.254.169.254/latest/identity-credentials/ec2/security-credentials/ec2-instance"
)

KUBERNETES_PATHS=(
    "/var/run/secrets/kubernetes.io" "/run/secrets/kubernetes.io" "/etc/kubernetes" "/var/lib/kubelet"
    "/var/lib/kubernetes" "/root/.kube/config" "/home/*/.kube/config" "/opt/kubeconfig"
)

DATABASE_PATTERNS=(
    "mysql://" "postgresql://" "postgres://" "mongodb://" "redis://" "oracle://" "sqlserver://"
    "jdbc:" "host=" "password=" "user=" "database="
)

WEB_CONFIG_FILES=(
    ".env" "config.php" "configuration.php" "wp-config.php" "settings.py" "config.json" "config.yml"
    "config.yaml" "application.properties" "appsettings.json" "web.config" "config.xml" "database.yml" "secrets.yml"
)

BACKUP_EXTENSIONS=(
    ".bak" ".backup" ".old" ".save" ".orig" ".tmp" ".temp" ".swp" ".swo" ".000" ".001"
)

show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                       Linux_EnumPE Tool                      ║"
    echo "║                Enumerate Privilege Escalation                ║"
    echo "║                      By Hernan Rodriguez                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬ SYSTEM OVERVIEW ▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬${NC}"
    echo -e "${YELLOW}[-] Report Directory: ${REPORT_DIR}/${NC}"
    echo -e "${YELLOW}[-] Current User: ${CURRENT_USER}${NC}"
    echo -e "${YELLOW}[-] Scan Date: ${CURRENT_DATE}${NC}"
    echo -e "${YELLOW}[-] Kernel Version: ${KERNEL_VERSION}${NC}"
    echo ""
}

init_report_dir() {
    if [ ! -d "$REPORT_DIR" ]; then
        mkdir -p "$REPORT_DIR"
        echo -e "${GREEN}[+] Created report directory: ${REPORT_DIR}/${NC}"
    else
        echo -e "${YELLOW}[!] Report directory already exists: ${REPORT_DIR}/${NC}"
    fi
}

system_information() {
    echo -e "${BLUE}[*] Gathering System Information...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}Hostname:${NC} $(hostname 2>/dev/null || echo 'N/A')"
    echo -e "${BOLD}Kernel Version:${NC} $KERNEL_VERSION"
    echo -e "${BOLD}Architecture:${NC} $(uname -m 2>/dev/null || echo 'N/A')"
    echo -e "${BOLD}Operating System:${NC} $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo 'N/A')"
    echo -e "${BOLD}Uptime:${NC} $(uptime 2>/dev/null | awk -F'( |,|:)+' '{if ($6=="days" || $6=="day") {print $4,$5",",$6,$7,"hours,",$8,"minutes"} else {print $4,$5,"hours,",$6,"minutes"}}' || echo 'N/A')"
    
    echo -e "${BOLD}Current User:${NC} $CURRENT_USER"
    echo -e "${BOLD}User ID:${NC} $(id 2>/dev/null || echo 'N/A')"
    
    echo -e "${BOLD}Available Shells:${NC}"
    if [ -f "/etc/shells" ]; then
        grep -v "^#" /etc/shells 2>/dev/null | while read -r shell; do
            echo -e "  - $shell"
        done
    else
        echo "  N/A"
    fi
    
    env 2>/dev/null | grep -v 'LS_COLORS' > "$REPORT_DIR/environment.txt"
    echo -e "${BOLD}Environment Variables:${NC} Saved to: ${REPORT_DIR}/environment.txt"
    
    echo "$PATH" > "$REPORT_DIR/path.txt"
    echo -e "${BOLD}PATH Variable:${NC} Saved to: ${REPORT_DIR}/path.txt"
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

kernel_checks() {
    echo -e "${BLUE}[*] Performing Kernel and Security Checks...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}Kernel Security Features:${NC}"
    
    if [ -r /proc/config.gz ]; then
        kconfig="zcat /proc/config.gz"
    elif [ -r "/boot/config-$(uname -r)" ]; then
        kconfig="cat /boot/config-$(uname -r)"
    else
        echo -e "  ${YELLOW}[!] Kernel config not accessible${NC}"
        return
    fi
    
    security_checks=(
        "CONFIG_CC_STACKPROTECTOR:Stack Protector"
        "CONFIG_DEBUG_STRICT_USER_COPY_CHECKS:Strict User Copy Checks" 
        "CONFIG_DEBUG_RODATA:Read-only Kernel Data"
        "CONFIG_STRICT_DEVMEM:Restrict /dev/mem Access"
        "CONFIG_DEVKMEM:Restrict /dev/kmem Access"
    )
    
    for check in "${security_checks[@]}"; do
        config=${check%:*}
        name=${check#*:}
        if $kconfig 2>/dev/null | grep -qi "^$config=y"; then
            echo -e "  ${GREEN}[✓] $name: Enabled${NC}"
        else
            echo -e "  ${YELLOW}[!] $name: Disabled${NC}"
        fi
    done
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

programming_languages() {
    echo -e "${BLUE}[*] Checking Available Programming Languages...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    local found_langs=()
    
    for lang_name in "${PROGRAMMING_LANGS[@]}"; do
        if command -v "$lang_name" >/dev/null 2>&1; then
            version=$("$lang_name" --version 2>/dev/null | head -n1 | sed 's/^[^0-9]*//' || echo "version unknown")
            found_langs+=("$lang_name: $version")
        fi
    done
    
    if [ ${#found_langs[@]} -gt 0 ]; then
        echo -e "${BOLD}Available Programming Languages:${NC}"
        for lang_info in "${found_langs[@]}"; do
            echo -e "  - $lang_info"
        done
    else
        echo -e "${YELLOW}  No common programming languages found${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

password_search() {
    echo -e "${BLUE}[*] Searching for Passwords and Credentials...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}Login Configuration (/etc/login.defs):${NC}"
    local umask_def=$(grep -i "^UMASK" /etc/login.defs 2>/dev/null)
    local login_defs=$(grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null)
    
    if [ "$umask_def" ]; then
        echo -e "  UMASK settings: $umask_def"
    fi
    if [ "$login_defs" ]; then
        echo -e "  Password policies:\n$login_defs"
    fi
    
    echo -e "${BOLD}Searching for files containing passwords...${NC}"
    
    password_patterns=("password" "pwd" "pass" "secret" "key" "credential" "token" "api_key")
    search_locations=("/etc" "/home" "/var/www" "/opt" "/tmp")
    
    for location in "${search_locations[@]}"; do
        if [ -d "$location" ]; then
            for pattern in "${password_patterns[@]}"; do
                find "$location" -type f \( -name "*.php" -o -name "*.txt" -o -name "*.conf" -o -name "*.config" -o -name "*.xml" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" -o -name ".env" \) \
                    2>/dev/null | xargs grep -l -i "$pattern" 2>/dev/null >> "$REPORT_DIR/password_files.txt"
            done
        fi
    done
    
    if [ -s "$REPORT_DIR/password_files.txt" ]; then
        echo -e "  ${YELLOW}[!] Potential password files found: ${REPORT_DIR}/password_files.txt${NC}"
        echo -e "  ${YELLOW}[!] Files count: $(wc -l < "$REPORT_DIR/password_files.txt")${NC}"
    else
        echo -e "  ${GREEN}[✓] No obvious password files found${NC}"
    fi
    
    echo -e "${BOLD}Checking Shell History...${NC}"
    history_files=("~/.bash_history" "~/.zsh_history" "~/.nano_history" "~/.mysql_history" "~/.php_history" "~/.python_history")
    sensitive_commands=("password" "passwd" "ssh" "mysql" "psql" "rdesktop" "su -" "sudo")
    
    local found_sensitive=false
    for hist_file in "${history_files[@]}"; do
        local expanded_file=$(eval echo "$hist_file")
        if [ -f "$expanded_file" ] && [ -r "$expanded_file" ]; then
            for cmd in "${sensitive_commands[@]}"; do
                local found=$(grep -i "$cmd" "$expanded_file" 2>/dev/null)
                if [ "$found" ]; then
                    if ! $found_sensitive; then
                        echo -e "  ${YELLOW}[!] Sensitive commands found in history files:${NC}"
                        found_sensitive=true
                    fi
                    echo -e "  ${RED}    [!] $hist_file contains: $cmd${NC}"
                    echo "$found" | head -10 | sed 's/^/        /'
                fi
            done
        fi
    done
    
    if ! $found_sensitive; then
        echo -e "  ${GREEN}[✓] No sensitive commands in shell history${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

ssh_checks() {
    echo -e "${BLUE}[*] Checking SSH Configuration...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    if [ -f "/etc/ssh/sshd_config" ]; then
        local permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | tail -1)
        local password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | tail -1)
        
        echo -e "${BOLD}SSH Daemon Configuration:${NC}"
        echo -e "  PermitRootLogin: $permit_root"
        echo -e "  PasswordAuthentication: $password_auth"
        
        if [[ "$permit_root" == *"yes"* ]]; then
            echo -e "  ${YELLOW}[!] Root login via SSH is allowed${NC}"
        else
            echo -e "  ${GREEN}[✓] Root login via SSH is restricted${NC}"
        fi
    else
        echo -e "  ${YELLOW}[!] SSH config file not found${NC}"
    fi
    
    echo -e "${BOLD}SSH Keys Found:${NC}"
    local found_keys=()
    
    for key_location in "${SSH_KEYS[@]}"; do
        local expanded_key=$(eval echo "$key_location")
        if [ -f "$expanded_key" ] && [ -r "$expanded_key" ]; then
            found_keys+=("$expanded_key")
        fi
    done
    
    if [ ${#found_keys[@]} -gt 0 ]; then
        echo -e "  ${RED}[!] SSH keys found:${NC}"
        for key in "${found_keys[@]}"; do
            echo -e "  ${YELLOW}    - $key${NC}"
        done
        printf "%s\n" "${found_keys[@]}" > "$REPORT_DIR/ssh_keys.txt"
        echo -e "  ${YELLOW}[!] SSH keys saved to: ${REPORT_DIR}/ssh_keys.txt${NC}"
    else
        echo -e "  ${GREEN}[✓] No accessible SSH keys found${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

filesystem_analysis() {
    echo -e "${BLUE}[*] Analyzing File System and Interesting Directories...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}World-Writable Directories:${NC}"
    find / -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null > "$REPORT_DIR/world_writable_dirs.txt"
    
    if [ -s "$REPORT_DIR/world_writable_dirs.txt" ]; then
        local dir_count=$(wc -l < "$REPORT_DIR/world_writable_dirs.txt")
        echo -e "  ${RED}[!] Found $dir_count world-writable directories: ${REPORT_DIR}/world_writable_dirs.txt${NC}"
        head -10 "$REPORT_DIR/world_writable_dirs.txt" | while read -r dir; do
            echo -e "  ${YELLOW}    - $dir${NC}"
        done
        if [ $dir_count -gt 20 ]; then
            echo -e "  ${YELLOW}    ... and $((dir_count - 20)) more${NC}"
        fi
    else
        echo -e "  ${GREEN}[✓] No unusual world-writable directories found${NC}"
    fi
    
    echo -e "${BOLD}SUID/SGID Files:${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null > "$REPORT_DIR/suid_sgid_files.txt"
    
    if [ -s "$REPORT_DIR/suid_sgid_files.txt" ]; then
        local suid_count=$(wc -l < "$REPORT_DIR/suid_sgid_files.txt")
        echo -e "  ${RED}[!] Found $suid_count SUID/SGID files: ${REPORT_DIR}/suid_sgid_files.txt${NC}"
        head -10 "$REPORT_DIR/suid_sgid_files.txt" | while read -r file; do
            echo -e "  ${YELLOW}    - $file${NC}"
        done
        if [ $suid_count -gt 20 ]; then
            echo -e "  ${YELLOW}    ... and $((suid_count - 20)) more${NC}"
        fi
    else
        echo -e "  ${GREEN}[✓] No SUID/SGID files found${NC}"
    fi

    echo -e "${BOLD}Checking Interesting Directories:${NC}"
    for directory in "${INTERESTING_DIRS[@]}"; do
        if [ -d "$directory" ] && [ -r "$directory" ]; then
            local file_count=$(find "$directory" -type f 2>/dev/null | wc -l)
            local dir_count=$(find "$directory" -type d 2>/dev/null | wc -l)
            echo -e "  ${YELLOW}[!] $directory - Files: $file_count, Directories: $dir_count${NC}"
        fi
    done

    echo -e "${BOLD}Log Files Accessibility:${NC}"
    local accessible_logs=()
    for log_file in "${LOG_FILES[@]}"; do
        if [ -f "$log_file" ] && [ -r "$log_file" ]; then
            accessible_logs+=("$log_file")
        fi
    done
    
    if [ ${#accessible_logs[@]} -gt 0 ]; then
        echo -e "  ${RED}[!] Accessible log files found: ${#accessible_logs[@]} files${NC}"
        printf "%s\n" "${accessible_logs[@]}" > "$REPORT_DIR/accessible_logs.txt"
        for log in "${accessible_logs[@]:0:5}"; do
            echo -e "  ${YELLOW}    - $log${NC}"
        done
        if [ ${#accessible_logs[@]} -gt 10 ]; then
            echo -e "  ${YELLOW}    ... and $(( ${#accessible_logs[@]} - 10 )) more${NC}"
        fi
    else
        echo -e "  ${GREEN}[✓] No unusual log file access${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

user_group_analysis() {
    echo -e "${BLUE}[*] Analyzing Users and Groups...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}User Information:${NC}"
    echo -e "  Current User: $CURRENT_USER"
    echo -e "  User ID: $(id -u 2>/dev/null)"
    echo -e "  Group ID: $(id -g 2>/dev/null)"
    echo -e "  Groups: $(groups 2>/dev/null)"
    
    echo -e "${BOLD}Users with UID 0 (root):${NC}"
    local root_users=$(grep -v -E "^#" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1 }')
    if [ "$root_users" ]; then
        echo -e "$root_users" | while read user; do
            echo -e "  ${RED}[!] $user${NC}"
        done
    else
        echo -e "  ${GREEN}[✓] Only root user has UID 0${NC}"
    fi
    
    echo -e "${BOLD}All Users:${NC}"
    cut -d: -f1 /etc/passwd 2>/dev/null > "$REPORT_DIR/users.txt"
    local user_count=$(wc -l < "$REPORT_DIR/users.txt" 2>/dev/null || echo 0)
    echo -e "  ${YELLOW}[!] Total users: $user_count - Saved to: ${REPORT_DIR}/users.txt${NC}"
    
    echo -e "${BOLD}Sudo Privileges:${NC}"
    if command -v sudo >/dev/null 2>&1; then
        sudo -l 2>/dev/null > "$REPORT_DIR/sudo_privileges.txt"
        if [ -s "$REPORT_DIR/sudo_privileges.txt" ]; then
            echo -e "  ${RED}[!] Sudo privileges found: ${REPORT_DIR}/sudo_privileges.txt${NC}"
            grep -E "(NOPASSWD|ALL)" "$REPORT_DIR/sudo_privileges.txt" 2>/dev/null | while read -r line; do
                echo -e "  ${YELLOW}    $line${NC}"
            done
        else
            echo -e "  ${GREEN}[✓] No sudo privileges for current user${NC}"
        fi
    else
        echo -e "  ${YELLOW}[!] Sudo not installed${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

cron_analysis() {
    echo -e "${BLUE}[*] Analyzing Cron Jobs and Scheduled Tasks...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}System Cron Directories:${NC}"
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")
    for cron_dir in "${cron_dirs[@]}"; do
        if [ -d "$cron_dir" ]; then
            local file_count=$(find "$cron_dir" -type f 2>/dev/null | wc -l)
            echo -e "  ${YELLOW}[!] $cron_dir - Files: $file_count${NC}"
            ls -la "$cron_dir" 2>/dev/null > "$REPORT_DIR/cron_${cron_dir##*/}.txt"
            
            # Mostrar contenido de archivos cron
            find "$cron_dir" -type f 2>/dev/null | head -10 | while read -r file; do
                echo -e "  ${YELLOW}    - $file${NC}"
                # Mostrar primeras líneas del contenido
                head -2 "$file" 2>/dev/null | sed 's/^/      /'
            done
        fi
    done

    echo -e "${BOLD}User Cron Jobs:${NC}"
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null > "$REPORT_DIR/user_crontab.txt"
        if [ -s "$REPORT_DIR/user_crontab.txt" ]; then
            echo -e "  ${RED}[!] User crontab found: ${REPORT_DIR}/user_crontab.txt${NC}"
            echo -e "  ${YELLOW}Content:${NC}"
            head -10 "$REPORT_DIR/user_crontab.txt" | while read -r line; do
                echo -e "  ${YELLOW}    $line${NC}"
            done
        else
            echo -e "  ${GREEN}[✓] No user crontab entries${NC}"
        fi
    else
        echo -e "  ${YELLOW}[!] crontab command not available${NC}"
    fi
    
    echo -e "${BOLD}All Users Cron Jobs:${NC}"
    local found_user_crons=false
    cut -d ":" -f 1 /etc/passwd 2>/dev/null | while read -r user; do
        user_cron=$(crontab -l -u "$user" 2>/dev/null)
        if [ -n "$user_cron" ]; then
            if ! $found_user_crons; then
                echo -e "  ${RED}[!] Found crontab for users:${NC}"
                found_user_crons=true
            fi
            echo -e "  ${YELLOW}    - User: $user${NC}"
            echo "$user_cron" | head -30 | sed 's/^/      /'
        fi
    done
    
    if ! $found_user_crons; then
        echo -e "  ${GREEN}[✓] No user crontab entries found for any user${NC}"
    fi
    
    echo -e "${BOLD}Writable Cron Files:${NC}"
    find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null > "$REPORT_DIR/writable_cron.txt"
    if [ -s "$REPORT_DIR/writable_cron.txt" ]; then
        echo -e "  ${RED}[!] Writable cron files found: ${REPORT_DIR}/writable_cron.txt${NC}"
        head -30 "$REPORT_DIR/writable_cron.txt" | while read -r file; do
            echo -e "  ${YELLOW}    - $file${NC}"

            ls -la "$file" 2>/dev/null | sed 's/^/      /'
        done
    else
        echo -e "  ${GREEN}[✓] No writable cron files${NC}"
    fi
    
    echo -e "${BOLD}Cron Files with Weak Permissions:${NC}"
    find /etc/cron* /var/spool/cron* -type f -perm -o+w 2>/dev/null > "$REPORT_DIR/weak_cron_perms.txt"
    if [ -s "$REPORT_DIR/weak_cron_perms.txt" ]; then
        echo -e "  ${RED}[!] Cron files with world-writable permissions:${NC}"
        head -30 "$REPORT_DIR/weak_cron_perms.txt" | while read -r file; do
            echo -e "  ${YELLOW}    - $file${NC}"
        done
    else
        echo -e "  ${GREEN}[✓] No cron files with weak permissions${NC}"
    fi

    echo -e "${BOLD}System Crontab (/etc/crontab):${NC}"
    if [ -f "/etc/crontab" ] && [ -r "/etc/crontab" ]; then
        echo -e "  ${YELLOW}[!] /etc/crontab is readable${NC}"
        head -30 "/etc/crontab" 2>/dev/null | while read -r line; do
            echo -e "  ${YELLOW}    $line${NC}"
        done
    else
        echo -e "  ${GREEN}[✓] /etc/crontab not accessible${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

network_analysis() {
    echo -e "${BLUE}[*] Gathering Network Information...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${BOLD}Network Interfaces:${NC}"
    if command -v ip >/dev/null 2>&1; then
        ip addr show 2>/dev/null | grep -E "inet " > "$REPORT_DIR/network_interfaces.txt"
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig 2>/dev/null | grep -E "inet " > "$REPORT_DIR/network_interfaces.txt"
    fi
    
    if [ -s "$REPORT_DIR/network_interfaces.txt" ]; then
        cat "$REPORT_DIR/network_interfaces.txt" | while read line; do
            echo -e "  ${YELLOW}$line${NC}"
        done
    fi

    echo -e "${BOLD}Active Network Connections:${NC}"
    if command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null > "$REPORT_DIR/network_connections.txt"
    elif command -v ss >/dev/null 2>&1; then
        ss -tulpn 2>/dev/null > "$REPORT_DIR/network_connections.txt"
    fi
    
    if [ -s "$REPORT_DIR/network_connections.txt" ]; then
        local conn_count=$(grep -c -E "(LISTEN|ESTABLISHED)" "$REPORT_DIR/network_connections.txt" 2>/dev/null || echo 0)
        echo -e "  ${YELLOW}[!] Active connections: $conn_count - Saved to: ${REPORT_DIR}/network_connections.txt${NC}"
        head -10 "$REPORT_DIR/network_connections.txt" | while read -r line; do
            echo -e "  ${YELLOW}    $line${NC}"
        done
    fi
    
    echo -e "${BOLD}ARP Table:${NC}"
    if command -v arp >/dev/null 2>&1; then
        arp -a 2>/dev/null > "$REPORT_DIR/arp_table.txt"
        if [ -s "$REPORT_DIR/arp_table.txt" ]; then
            echo -e "  ${YELLOW}[!] ARP entries saved to: ${REPORT_DIR}/arp_table.txt${NC}"
        fi
    fi
    
    echo -e "${BOLD}DNS Configuration:${NC}"
    if [ -f "/etc/resolv.conf" ]; then
        grep -v "^#" /etc/resolv.conf 2>/dev/null > "$REPORT_DIR/dns_config.txt"
        echo -e "  ${YELLOW}[!] DNS config saved to: ${REPORT_DIR}/dns_config.txt${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

docker_checks() {
    echo -e "${BLUE}[*] Performing Docker Privilege Escalation Checks...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    if groups | grep -q '\bdocker\b'; then
        echo -e "${RED}[!] CRITICAL: User is member of 'docker' group${NC}"
        echo -e "${YELLOW}[-] Docker group membership provides root-level access${NC}"
        
        if [ -S "/var/run/docker.sock" ]; then
            local sock_perms=$(ls -la /var/run/docker.sock 2>/dev/null)
            echo -e "${YELLOW}[-] Docker socket found: /var/run/docker.sock${NC}"
            echo -e "${YELLOW}[-] Socket permissions: $sock_perms${NC}"
        fi
    else
        echo -e "${GREEN}[✓] User not in docker group${NC}"
    fi
    
    if command -v docker &> /dev/null; then
        echo -e "${CYAN}[-] Running Docker Containers:${NC}"
        docker ps 2>/dev/null | head -10
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

lxd_checks() {
    echo -e "${BLUE}[*] Performing LXD/LXC Privilege Escalation Checks...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    if groups | grep -q '\blxd\b'; then
        echo -e "${RED}[!] CRITICAL: User is member of 'lxd' group${NC}"
        echo -e "${YELLOW}[-] LXD group membership can lead to root privilege escalation${NC}"
    else
        echo -e "${GREEN}[✓] User not in lxd group${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

cloud_metadata_enum() {
    echo -e "${BLUE}[*] Performing Cloud Metadata Enumeration...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    local cloud_found=false
    
    local cloud_indicators=0
    
    if hostname | grep -q -E "ec2|aws|azure|gcp|google"; then
        cloud_indicators=$((cloud_indicators+1))
    fi
    
    if ip route | grep -q "169.254.0.0"; then
        cloud_indicators=$((cloud_indicators+1))
    fi
    
    if [ -f "/sys/hypervisor/uuid" ] || [ -d "/proc/xen" ]; then
        cloud_indicators=$((cloud_indicators+1))
    fi
    
    if [ $cloud_indicators -eq 0 ]; then
        echo -e "${GREEN}[✓] No cloud environment detected - Skipping cloud checks${NC}"
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo ""
        return
    fi
    
    echo -e "${YELLOW}[-] Cloud environment detected - Running quick checks...${NC}"
    
    local quick_cloud_check=false
    
    if command -v curl >/dev/null 2>&1; then
        response=$(timeout 1 curl -s -f "http://169.254.169.254/latest/meta-data/" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        response=$(timeout 1 wget -q -O - "http://169.254.169.254/latest/meta-data/" 2>/dev/null)
    fi
    
    if [ -n "$response" ]; then
        echo -e "${RED}[!] CLOUD METADATA FOUND${NC}"
        echo -e "${YELLOW}$response${NC}" | head -10
        quick_cloud_check=true
    else
        echo -e "${GREEN}[✓] No cloud metadata accessible${NC}"
    fi
    
    echo -e "${CYAN}[-] Quick cloud credential scan...${NC}"
    
    local quick_cred_files=(
        "/etc/aws/credentials"
        "/root/.aws/credentials" 
        "/home/$CURRENT_USER/.aws/credentials"
    )
    
    for cred_file in "${quick_cred_files[@]}"; do
        if [ -f "$cred_file" ] && [ -r "$cred_file" ]; then
            echo -e "${RED}[!] Cloud credentials found: $cred_file${NC}"
            quick_cloud_check=true
        fi
    done
    
    if ! $quick_cloud_check; then
        echo -e "${GREEN}[✓] No cloud credentials found${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

kubernetes_assessment() {
    echo -e "${BLUE}[*] Performing Kubernetes Security Assessment...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    local k8s_found=false

    echo -e "${CYAN}[-] Checking Kubernetes Paths...${NC}"
    for k8s_path in "${KUBERNETES_PATHS[@]}"; do
        expanded_path=$(eval echo $k8s_path 2>/dev/null)
        if [ -e "$expanded_path" ]; then
            echo -e "${YELLOW}[!] Kubernetes path found: $expanded_path${NC}"
            k8s_found=true
        fi
    done
    
    if command -v kubectl >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] kubectl is available${NC}"
        k8s_found=true
    fi
    
    if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        echo -e "${RED}[!] Running inside Kubernetes pod${NC}"
        k8s_found=true
    fi
    
    if ! $k8s_found; then
        echo -e "${GREEN}[✓] No Kubernetes components found${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

kernel_exploit_suggester() {
    echo -e "${BLUE}[*] Running Automated Kernel Exploit Suggester...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${CYAN}[-] Kernel Information:${NC}"
    echo -e "${YELLOW}    Version: $KERNEL_VERSION${NC}"
    echo -e "${YELLOW}    Architecture: $(uname -m)${NC}"
    
    local exploits_found=()
    
    # DirtyCow check
    if [[ "$KERNEL_VERSION" =~ ^3\.[0-9]\. ]] || [[ "$KERNEL_VERSION" =~ ^4\.[0-8]\. ]] || [[ "$KERNEL_VERSION" =~ ^4\.9\.[0-9] ]]; then
        exploits_found+=("DirtyCow (CVE-2016-5195)")
    fi
    
    # DirtyPipe check
    if [[ "$KERNEL_VERSION" =~ ^5\.8 ]] || [[ "$KERNEL_VERSION" =~ ^5\.1[0-9] ]] || [[ "$KERNEL_VERSION" =~ ^5\.1[0-5] ]]; then
        exploits_found+=("DirtyPipe (CVE-2022-0847)")
    fi
    
    # PwnKit check
    if pkexec --version 2>/dev/null | grep -q "polkit"; then
        exploits_found+=("PwnKit (CVE-2021-4034)")
    fi
    
    if [ ${#exploits_found[@]} -gt 0 ]; then
        echo -e "${RED}[!] POTENTIAL EXPLOITS FOUND:${NC}"
        for exploit in "${exploits_found[@]}"; do
            echo -e "${YELLOW}    - $exploit${NC}"
        done
    else
        echo -e "${GREEN}[✓] No obvious kernel exploits detected${NC}"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

process_memory_mining() {
    echo -e "${BLUE}[*] Mining Credentials from Process Memory...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${CYAN}[-] Quick process memory scan...${NC}"
    
    ssh_pids=$(pgrep ssh 2>/dev/null)
    if [ -n "$ssh_pids" ]; then
        echo -e "${YELLOW}[!] SSH processes found: $ssh_pids${NC}"
    fi

    db_processes=("mysql" "postgres" "redis" "mongod")
    for db_proc in "${db_processes[@]}"; do
        db_pids=$(pgrep "$db_proc" 2>/dev/null)
        if [ -n "$db_pids" ]; then
            echo -e "${YELLOW}[!] $db_proc processes found: $db_pids${NC}"
        fi
    done
    
    echo -e "${GREEN}[✓] Process memory scan completed${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

database_connection_extraction() {
    echo -e "${BLUE}[*] Extracting Database Connection Strings...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${CYAN}[-] Quick database connection scan...${NC}"
    
    search_paths=("/var/www" "/opt" "/home/$CURRENT_USER")
    
    for search_path in "${search_paths[@]}"; do
        if [ -d "$search_path" ]; then
            for pattern in "${DATABASE_PATTERNS[@]}"; do
                found=$(grep -r -i "$pattern" "$search_path" 2>/dev/null | head -10)
                if [ -n "$found" ]; then
                    echo -e "${YELLOW}[!] Database connections in $search_path:${NC}"
                    echo -e "$found"
                fi
            done
        fi
    done
    
    echo -e "${GREEN}[✓] Database connection scan completed${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

web_config_scanning() {
    echo -e "${BLUE}[*] Scanning Web Application Configurations...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${CYAN}[-] Quick web config scan...${NC}"

    web_roots=("/var/www" "/opt/lampp/htdocs" "/home/$CURRENT_USER/public_html")
    
    for web_root in "${web_roots[@]}"; do
        if [ -d "$web_root" ]; then
            for config_file in "${WEB_CONFIG_FILES[@]}"; do
                found_files=$(find "$web_root" -name "$config_file" -type f 2>/dev/null)
                if [ -n "$found_files" ]; then
                    echo -e "${YELLOW}[!] Web config found in $web_root:${NC}"
                    echo -e "$found_files"
                fi
            done
        fi
    done
    
    echo -e "${GREEN}[✓] Web config scan completed${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

backup_file_discovery() {
    echo -e "${BLUE}[*] Discovering Backup Files...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "${CYAN}[-] Quick backup file scan...${NC}"
    
    for extension in "${BACKUP_EXTENSIONS[@]}"; do
        found_files=$(find /var /home /opt /etc -name "*$extension" -type f 2>/dev/null)
        if [ -n "$found_files" ]; then
            echo -e "${YELLOW}[!] Backup files found (*$extension):${NC}"
            echo -e "$found_files"
        fi
    done
    
    vcs_files=$(find /var /home /opt -name ".git" -o -name ".svn" -o -name ".hg" -type d 2>/dev/null)
    if [ -n "$vcs_files" ]; then
        echo -e "${YELLOW}[!] Version control directories found:${NC}"
        echo -e "$vcs_files"
    fi
    
    echo -e "${GREEN}[✓] Backup file scan completed${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

main() {
    show_banner
    init_report_dir
    
    echo -e "${GREEN}[*] Starting Advanced Linux_EnumPE Scan...${NC}"
    echo ""
    
    system_information
    kernel_checks
    programming_languages
    user_group_analysis
    network_analysis
    ssh_checks
    filesystem_analysis
    cron_analysis
    password_search
    docker_checks
    lxd_checks
    cloud_metadata_enum
    kubernetes_assessment
    kernel_exploit_suggester
    process_memory_mining
    database_connection_extraction
    web_config_scanning
    backup_file_discovery
    
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SCAN COMPLETE                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬ SCAN SUMMARY ▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬${NC}"
    echo -e "${BOLD}Generated Reports in: ${REPORT_DIR}/${NC}"
    echo ""
    
    if ls "$REPORT_DIR"/*.txt >/dev/null 2>&1; then
        echo -e "${CYAN}[-] Generated Reports:${NC}"
        for file in "$REPORT_DIR"/*.txt; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                filesize=$(du -h "$file" | cut -f1)
                echo -e "${YELLOW}    $filename ${NC}"
            fi
        done
    fi
    
    echo ""
    echo -e "${RED}[!] CRITICAL ENUMERATION AREAS:${NC}"
    echo -e "${YELLOW}[-] System Information & Kernel Security${NC}"
    echo -e "${YELLOW}[-] User Privileges & Sudo Access${NC}"
    echo -e "${YELLOW}[-] Container Security (Docker/LXD)${NC}"
    echo -e "${YELLOW}[-] Cloud & Kubernetes Assessment${NC}"
    echo -e "${YELLOW}[-] Credential Mining & Config Scanning${NC}"
    echo ""
    echo -e "${GREEN}[✓] Advanced enumeration completed successfully!${NC}"
    echo -e "${YELLOW}[-] Total execution time: ~30-60 seconds${NC}"
}

if [ -z "$BASH_VERSION" ]; then
    echo -e "${RED}Error: This script must be run with bash${NC}"
    exit 1
fi

main "$@"
