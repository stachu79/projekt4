## Pentesting machine musstachio

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
The machine exists as a virtual machine, which can be accessed from [this link](https://tryhackme.com/room/musstachio)
The tests were carried out by using whitebox.

#### Most severe vulnerabilites idenifies




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

2023-05-07 version 1.0 Final version of the report after carried tests out.

### Process of exploiting machine

#### Summary

During the process some technics were used to get finnaly root privileges. Root privileges has been gain as a result of misconfiguration, poorly password protection and use of documented vulnerability. Methods and technics were used:

-port scanning

-webapp attacks

-code injection

-XXE injection

-exploitation

-password cracking

-brute forcing


#### Prerequisites for the attack

Local internet access - Victim's IP Address: 10.10.10.193

#### Technical details (Proof of concept)

First of all we needed to discover services at victim's machine

![](https://github.com/stachu79/projekt4/blob/main/musstachio/rustscan1.png)
![](https://github.com/stachu79/projekt4/blob/main/musstachio/rustscan2.png)

Detailed scan showed services on machine.
```
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 581b0c0ffacf05be4cc07af1f188611c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2WTNk2XxeSH8TaknfbKriHmaAOjRnNrbq1/zkFU46DlQRZmmrUP0uXzX6o6mfrAoB5BgoFmQQMackU8IWRHxF9YABxn0vKGhCkTLquVvGtRNJjR8u3BUdJ/wW/HFBIQKfYcM+9agllshikS1j2wn28SeovZJ807kc49MVmCx3m1OyL3sJhouWCy8IKYL38LzOyRd8GEEuj6QiC+y3WCX2Zu7lKxC2AQ7lgHPBtxpAgKY+txdCCEN1bfemgZqQvWBhAQ1qRyZ1H+jr0bs3eCjTuybZTsa8aAJHV9JAWWEYFegsdFPL7n4FRMNz5Qg0BVK2HGIDre343MutQXalAx5P
|   256 3cfce8a37e039a302c77e00a1ce452e6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCEPDv6sOBVGEIgy/qtZRm+nk+qjGEiWPaK/TF3QBS4iLniYOJpvIGWagvcnvUvODJ0ToNWNb+rfx6FnpNPyOA0=
|   256 9d59c6c779c554c41daae4d184710192 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGldKE9PtIBaggRavyOW10GTbDFCLUZrB14DN4/2VgyL
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
8765/tcp open  http    syn-ack ttl 63 nginx 1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Mustacchio | Login
|_http-server-header: nginx/1.10.3 (Ubuntu)

```



I saw, that http service is running on machine. I opened the page.
Default page:

![](https://github.com/stachu79/projekt4/blob/main/musstachio/web80.png)

Nothing to see here. Next step was to check another web server running at 8765 port. 

![](https://github.com/stachu79/projekt4/blob/main/musstachio/web8765.png)

The standard login and password like "admin/admin" didn't work.
So I started fuzzing directories on web server

![](https://github.com/stachu79/projekt4/blob/main/musstachio/ffuf.png)

After a while I got directories on server. I looked into that directories and received folder ```/custom``` where were two folders ```/css``` and ```/js```

![](https://github.com/stachu79/projekt4/blob/main/musstachio/custom1.png)

In folder ```/custom/js``` I found an interesting file called ```users.bak```

![](https://github.com/stachu79/projekt4/blob/main/musstachio/customjs1.png)

I downloaded that file into my local machine and checked what type of a file it was

![](https://github.com/stachu79/projekt4/blob/main/musstachio/users.png)

I found out that was a sqlite file. I managed to open the file and there was a one table called ```users```

![](https://github.com/stachu79/projekt4/blob/main/musstachio/sqlite1.png)

I dumped that table and I got user ```admin``` and hashed password.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/sqlite2.png)

I used a webpage to unhash the password and I received plain password.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/pass.png)

I logged into the admin web server at port 8765

![](https://github.com/stachu79/projekt4/blob/main/musstachio/login.png)

and I got the web page where I could post a comment

![](https://github.com/stachu79/projekt4/blob/main/musstachio/admin1.png)

I checked the source of that page and got another interesting location ```/auth/dontforget.bak``` and information that user called ```Barry``` is using SSH.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/source1.png)

So I downloaded that file and checked what type of a file it was.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/filedont.png)

I opened that file and got information that if we want to put comment to the webpage we need to use XML format and desired structure for XML.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/xml.png)

I checked if server is protected from XXE (XML external entity) injection

![](https://github.com/stachu79/projekt4/blob/main/musstachio/testxxe.png)

and I discovered that server had that vulnerability.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/resultxxe.png)

Because I descovered that user ```barry``` is using SSH so I tried to obtain his SSH private key ```id_rsa```

![](https://github.com/stachu79/projekt4/blob/main/musstachio/id_rsa.png)

I succedded

![](https://github.com/stachu79/projekt4/blob/main/musstachio/id_rsa2.png)

I put that file in my local machine and prepared to crack it using "John the ripper"

![](https://github.com/stachu79/projekt4/blob/main/musstachio/id_rsa3.png)

![](https://github.com/stachu79/projekt4/blob/main/musstachio/ssh2john.png)

After that I cracked password using "John the Ripper"

![](https://github.com/stachu79/projekt4/blob/main/musstachio/id_rsa_hash.png)

and was able to log in using SSH protocol

![](https://github.com/stachu79/projekt4/blob/main/musstachio/barrylogin.png)

After I logged in I obtained user flag.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/userflag.png)

I checked if some proccesses had a SUID (Set owner User ID up on execution) bit set up.

![](https://github.com/stachu79/projekt4/blob/main/musstachio/suid.png)

I found out that one executive file is interesting for privilege escalation. That file was a ```live_log``` which was placed in home folder of another user called ```joe```.
I could run this program so I did it 

![](https://github.com/stachu79/projekt4/blob/main/musstachio/live_logrun.png)

Then I checked strings included into that progam 

![](https://github.com/stachu79/projekt4/blob/main/musstachio/live_logstrings.png)

and found that where is a system program called ```tail``` was used

![](https://github.com/stachu79/projekt4/blob/main/musstachio/live_logtail.png)

but without direct path to the executable so I prepared a file in the ```/tmp``` directory called ```tail```

![](https://github.com/stachu79/projekt4/blob/main/musstachio/tmptail.png)

where I insterted that payload: 

![](https://github.com/stachu79/projekt4/blob/main/musstachio/payload.png)

After that I had to change ```PATH``` variable

![](https://github.com/stachu79/projekt4/blob/main/musstachio/exportpath.png)

also I had to change permitions to ```/tmp/tail``` as executive file
and then I escalated privileges running ```live_log``` program

![](https://github.com/stachu79/projekt4/blob/main/musstachio/privesc.png)

and I could read the root flag

![](https://github.com/stachu79/projekt4/blob/main/musstachio/rootflag.png)

#### Recommendation

- don't leave fragile comments in HTML code
- set up web server to avoid XXE injection
- in custom executable file use direct path to system binaries to avoid replacing by attacker.
