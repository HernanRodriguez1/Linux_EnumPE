# Linux_EnumPE - Privilege Escalation Tool

![Banner](https://img.shields.io/badge/Linux-PrivEsc%20Enumeration-red) ![Version](https://img.shields.io/badge/Version-1.0-blue) 

**Linux_EnumPE** is a comprehensive privilege escalation enumeration tool designed for professional penetration testers and security researchers. It performs deep system reconnaissance across multiple attack surfaces including kernel vulnerabilities, container escape vectors, cloud misconfigurations, application security flaws, and access control weaknesses. The tool automates the discovery of privilege escalation paths through exhaustive analysis of system configurations, running services, file permissions, environment settings, and security controls, providing security professionals with a complete assessment of potential escalation vectors in Linux environments.

## Features

### **System Enumeration**
- **System Information**: Hostname, kernel version, architecture, OS details
- **User & Group Analysis**: Current user, UID 0 users, group memberships
- **Environment Variables**: Complete environment dump and PATH analysis
- **Available Shells**: All installed shells on the system

### **Security Assessment** 
- **Kernel Vulnerability Checks**: DirtyCow, DirtyPipe, PwnKit detection
- **Security Feature Verification**: Stack protector, ASLR, kernel security features
- **SUID/SGID Binaries**: All privileged binaries with execution rights
- **Sudo Privileges**: Sudoers configuration and NOPASSWD commands

### **Privilege Escalation Vectors**
- **Docker & LXD Group Membership**: Container escape possibilities
- **Writable Cron Jobs**: Scheduled tasks with weak permissions
- **SSH Configuration**: SSH daemon settings and key discovery
- **World-Writable Directories**: Globally accessible directories

### **Advanced Techniques**
- **Cloud Metadata Enumeration**: AWS, Azure, GCP instance metadata
- **Kubernetes Security Assessment**: K8s configs, tokens, and pod access
- **Database Connection Extraction**: DB connection strings and credentials
- **Web Application Config Scanning**: .env files, config.php, wp-config.php
- **Process Memory Credential Mining**: Credentials in running processes
- **Backup File Discovery**: Backup files, database dumps, version control

### **Network & Services**
- **Network Interfaces**: IP addresses and network configuration
- **Active Connections**: Listening services and established connections
- **DNS Configuration**: Resolv.conf and DNS settings
- **ARP Table**: Network neighbor discovery

### **System Configuration**
- **Cron Jobs**: System and user scheduled tasks
- **Log File Access**: Accessible system logs
- **Password Files**: Files containing credentials and secrets
- **Weak Permissions**: Files and directories with insecure permissions

## Installation & Usage

### Quick Install
```bash
# Download script
wget -q https://raw.githubusercontent.com/HernanRodriguez1/Linux_EnumPE/refs/heads/main/Linux_EnumPE.sh
chmod +x Linux_EnumPE.sh
./Linux_EnumPE.sh
```

### Method 2: Direct Execution
```bash
# One-liner download and execute
curl -sL https://raw.githubusercontent.com/HernanRodriguez1/Linux_EnumPE/refs/heads/main/Linux_EnumPE.sh | bash
```

![1](https://github.com/user-attachments/assets/d7394ab7-5fe7-4f61-bd24-c610a9289a5c)
![2](https://github.com/user-attachments/assets/50670e1b-f5b2-4c0e-9d6d-b550624788b9)
![3](https://github.com/user-attachments/assets/68063300-30c1-4a8e-8487-b2c9645ced9e)
![4](https://github.com/user-attachments/assets/043a4328-29c8-41c3-8138-486abf07fd97)
![5](https://github.com/user-attachments/assets/cd41dfa6-9978-44a8-92f2-d4b28d4ccedf)
![6](https://github.com/user-attachments/assets/d96bdf5b-95d2-4010-9c1e-cda633afba8a)
![7](https://github.com/user-attachments/assets/43877c65-f55c-4ed5-823e-54e954e6af5a)

## Generated Reports

All reports are saved to `Linux_EnumPE_Reports/` directory:

| Report File | Description |
|-------------|-------------|
| `accessible_logs.txt` | Accessible system log files |
| `arp_table.txt` | ARP table entries |
| `cron_cron.daily.txt` | Daily cron jobs |
| `cron_cron.d.txt` | System cron jobs |
| `cron_cron.hourly.txt` | Hourly cron jobs |
| `cron_cron.monthly.txt` | Monthly cron jobs |
| `cron_cron.weekly.txt` | Weekly cron jobs |
| `dns_config.txt` | DNS configuration |
| `environment.txt` | Environment variables |
| `network_connections.txt` | Active network connections |
| `network_interfaces.txt` | Network interfaces |
| `password_files.txt` | Files containing passwords |
| `path.txt` | PATH environment variable |
| `ssh_keys.txt` | SSH keys and configurations |
| `sudo_privileges.txt` | Sudo permissions |
| `suid_sgid_files.txt` | SUID/SGID binaries |
| `user_crontab.txt` | User cron jobs |
| `users.txt` | System users |
| `weak_cron_perms.txt` | Cron files with weak permissions |
| `world_writable_dirs.txt` | World-writable directories |
| `writable_cron.txt` | Writable cron files |


## Legal Disclaimer

This tool is designed for:
- Authorized penetration testing
- Security research
- Educational purposes
- Red team exercises

**Unauthorized use on systems you don't own is illegal.**
---
