# Projekt4 - webapplications pentesting

The main goal of the project was to solve machines in TryHackMe portal

The machines was:

[1. Psycho Break](https://tryhackme.com/room/psychobreak) - IP Address 10.10.137.177

[2. Mustacchio](https://tryhackme.com/room/mustacchio) - IP Address 10.10.10.193

[3. Overpass](https://tryhackme.com/room/overpass) - IP Address 10.10.42.81

[4. 0Day](https://tryhackme.com/room/0day) - IP Address 10.10.191.236


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

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/rustscan1.png)
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/rustscan2.png)

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



3.  We so, that http service is running on machine. We opened the page.
    Default page:

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/webpage01.png)

Nothing to see here. Next step was to check HTML code. 
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/sourcecode.png)

There was a comment that point to a different page.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/sadistroom.png)

This page gave us a key, which I need to go to another room.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/key1.png)

In the locker room, I have another link to the map. This time it’s a php file. There was an encoded text that I needed to decode to access the map. 

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/lockerroom.png)

To decode text I used Cyberchef and Atbash Cipher

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/cyberchef.png)

After I provided decoded text I received another webpage called map

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/map.png)

The map contains the two room I already accessed, and two other.

Safe Heaven

The Abandoned Room

##### Safe Heaven
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/safeheaven.png)
This room contains a gallery with a few images. The source code also contain the following comment.

```
<!-- I think I'm having a terrible nightmare. Search through me and find it ... -->
```

I launched GoBuster through ```/SafeHeaven/``` folder
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/gobuster2.png)

and after awhile I receive ```/keeper``` folder.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/keeper.png)

I clicked on the Escape button. Which took me to a page that shows some stairs and gave me 1m 45s to find where the image was taken.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/escape.png)
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/googleit.png)

I found picture in Google 
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/lighthouse.png)

When I inserted name of the lighthouse I received another key which allowed me to go further.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/key2.png)

##### Abandoned Room














#### Recommendation

- eliminate possibility to inject code on `/admin` page
- consider to restrict code execution of some tools
- eliminate possibility of use vulnerability described as [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034)
- try no to hold passwords and/or hashes written in a files within filesystem (inside docker) and accessible to everybody.



