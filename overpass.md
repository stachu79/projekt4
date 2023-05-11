## Pentesting machine Overpass

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
The machine exists as a virtual machine, which can be accessed from [this link](https://tryhackme.com/room/overpass)
The tests were carried out by using whitebox.

#### Most severe vulnerabilites idenifies

- Cookie poisoning
- Base Score 9.8
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H


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

-cookie poisoning

-exploitation

-password cracking

-brute forcing


#### Prerequisites for the attack

Local internet access - Victim's IP Address: 10.10.42.81

#### Technical details (Proof of concept)

First of all we needed to discover services at victim's machine

![](https://github.com/stachu79/projekt4/blob/main/Overpass/rustscan1.png)
![](https://github.com/stachu79/projekt4/blob/main/Overpass/nmap.png)

I checked web page and got 
![](https://github.com/stachu79/projekt4/blob/main/Overpass/web80.png)

I checked source code of that page and found one directory called ```/downloads```
![](https://github.com/stachu79/projekt4/blob/main/Overpass/source1.png)


I started to enumerate directories to find another folders in webserver using ```dirb``` program

![](https://github.com/stachu79/projekt4/blob/main/Overpass/dirb.png)

I got login page so I checked source of that page

![](https://github.com/stachu79/projekt4/blob/main/Overpass/overadmin1.png)

Using ```Developer tools``` from web browser I got the all files from login page. 

![](https://github.com/stachu79/projekt4/blob/main/Overpass/devtools1.png)

I checked all files and in ```login.js``` script I found that variable called ```statusOrCookie``` could be changed for random value to log into the web page

![](https://github.com/stachu79/projekt4/blob/main/Overpass/javascript1.png)

I changed that value 

![](https://github.com/stachu79/projekt4/blob/main/Overpass/cookieset.png)

and after reload of webpage I was logged in without putting right credentials

![](https://github.com/stachu79/projekt4/blob/main/Overpass/overadmin2.png)

I copied the id_rsa key which was put into the web page

![](https://github.com/stachu79/projekt4/blob/main/Overpass/id_rsa1.png)

![](https://github.com/stachu79/projekt4/blob/main/Overpass/id_rsa2.png)

Then I prepared the ```id_rsa``` file for ```John the Ripper```  to extract password

![](https://github.com/stachu79/projekt4/blob/main/Overpass/id_rsa_hash.png)

Finally I got the user password

![](https://github.com/stachu79/projekt4/blob/main/Overpass/id_rsa_john.png)

I was able to log in using SSH

![](https://github.com/stachu79/projekt4/blob/main/Overpass/login.png)

I obtained user flag

![](https://github.com/stachu79/projekt4/blob/main/Overpass/userflag.png)

I downloaded a program called ```linpeas``` to the victim from my machine to enumerate all vulnerabilities and run it

![](https://github.com/stachu79/projekt4/blob/main/Overpass/linpeas.png)

After I analyzed the result I found that one program is executed by ```root``` user every minute
 
![](https://github.com/stachu79/projekt4/blob/main/Overpass/linpeasdetails.png)

and the ```/etc/hosts``` is writeable for everyone

![](https://github.com/stachu79/projekt4/blob/main/Overpass/hosts_write.png)

First I read the ```/etc/hosts``` file

![](https://github.com/stachu79/projekt4/blob/main/Overpass/hosts1.png)

Bacause cron job was reaching for a file to ```overpass.thm``` web location I changed the line in that file

![](https://github.com/stachu79/projekt4/blob/main/Overpass/hosts4.png)

After that I prepared folders like in the cron job

![](https://github.com/stachu79/projekt4/blob/main/Overpass/folders.png)

and the ```buildscript.sh``` file to get root flag

![](https://github.com/stachu79/projekt4/blob/main/Overpass/payload.png)

Then I created file in ```/tmp``` location according to the payload and set right permitions to that file

![](https://github.com/stachu79/projekt4/blob/main/Overpass/rootflag1.png)

I started the http server

![](https://github.com/stachu79/projekt4/blob/main/Overpass/pythonserver.png)

and after one minute I got root flag in ```/tmp/flag```

![](https://github.com/stachu79/projekt4/blob/main/Overpass/rootflag2.png)

without privilege escalation.



#### Recommendation

- don't leave fragile comments in HTML code
- don't put fragile data in web page
- don't use exact cookie value to check login
- set right permitions to the system files
- don't use cron jobs with higher permitions than necessary
