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

- Command injection - 
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/assesment.png)
CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:N/MAC :L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H

- Crontab - 


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

First of all we needed to discover services at the victim's machine

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/rustscan1.png)
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/rustscan2.png)

Detailed scan showed services on machine.
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



I noticed, that the http service is running on the machine. I opened the page.
Default page:

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/webpage01.png)

Nothing to see here. Next step was to check HTML code. 

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/sourcecode.png)

There was a comment that pointed to a different page.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/sadistroom.png)

This page gave us a key, which I need to proceed to another room.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/key1.png)

In the locker room, I had another link to the map. This time it was a php file. There was an encoded text that I needed to decode in order to access the map. 

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/lockerroom.png)

In order to decode the text Cyberchef and Atbash Cipher were used.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/cyberchef.png)

After I provided the decoded text I received another webpage which was called "map"

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/map.png)

The map contained the two rooms which I had already accessed and another two .

- Safe Heaven

- The Abandoned Room

##### Safe Heaven
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/safeheaven.png)

This room contained a gallery with a few images. The source code also contained the following comment.

```
<!-- I think I'm having a terrible nightmare. Search through me and find it ... -->
```

I launched GoBuster through ```/SafeHeaven/``` folder

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/gobuster2.png)

and after a while I received ```/keeper``` folder.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/keeper.png)

I clicked the Escape button which took me to a page that showed some stairs and gave me 1m 45s to find where the image had been taken.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/escape.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/googleit.png)

I found picture in Google 

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/lighthouse.png)

When I entered the name of the lighthouse I received another key which allowed me to go further.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/key2.png)

##### Abandoned Room
The next room on the map is the Abandoned Room. I had to provide the Keeper Key to enter it.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/abandonedroom.png)

When I clicked "Go further" I got into Laura's room

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/laura.png)

I checked page source, it says there is a shell on that page
```
<!-- There is something called "shell" on current page maybe that'll help you to get out of here !!!-->
```
which I prove using ```?shell=ls```

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/shell.png)

then I checked if I can go higher in filesystem, so I try ```?shell=ls ..``` and I got result

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/shell2.png)

I found that there was a another folder in ```/abandonedroom``` and in that direcrory I found two files

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/directory.png)

I downloaded those files and in zip files were also two files

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/helpme_content.png)

I extracted zip file and tried to open file Table.jpg which caused an error, so I looked what is a file and found that JPEG file is a zip file.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/table1.png)

I extracted zip file and got another two files.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/table2.png)

I listened to wav file I discover that is a message in morse code
I used a webpage to decrypt the message

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/morsecode.png)

and that was a password to extract data from JPEG file, because there was used steganography to hide text file into JPEG.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/morsekey.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/steghide1.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/extracteddata.png)

I read text file where was a credentials to log into ftp server

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/ftp.png)

I logged in to ftp server and found two files ```program``` and ```random.dic```

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/ftp2.png)

I downloaded those files and found that random.dic is a file with passwords to file called program. When I chose wrong password "program" said is Incorrect.
So I wrote small Python script. That script opened file "random.dic", take one word form file and run file "program"

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/script.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/scriptresult.png)

When script was running I got one correct result, so I managed to know that user for another service is kidman and I needed to decode password.
I checked the string of numbers in webpage and get result as on the pictures below.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/recognize1.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/recognize2.png)

and got password for user kidman

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/password.png)

Then I tried to log in to server using ssh 

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/ssh1.png)

and obtained user flag

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/userflag.png)

also found two hidden files in kidman's home directory

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/kidman1.png)

Then I tried to find commands to escalate privileges to root user using ```sudo -l``` command but user "kidman" couldn't use sudo, 
so I checked cron table using ```cat /etc/crontab``` command.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/crontab1.png)

In crontab I found one command which is non-standard and is executed with root privileges.
That was python script which anyone can change, so I wrote payload and set up listener in my machine. 

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/crontab2.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/payload.png)

After approx. two minutes I gained shell with root privileges and I could read root flag.
![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/root.png)

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/rootflag.png)

At the end with hint from TryHackMe I deleted ruvik account.

![](https://github.com/stachu79/projekt4/blob/main/PsychoBreak/defeatruvik.png)


#### Recommendation

- don't leave fragile comments in HTML code
- set up web server to avoid shell injection
- avoid setting up crontab with higher privileges than necessary
