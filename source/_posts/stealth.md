---
title: Stealth
date: 2023-09-15 11:30:03
updated: 2025-09-15 02:04:20
tags:
  - Metasploit-ctf
categories:
  - writeups
top_img: /ouhboy/images/cyberpunk-red.png
cover: https://malw0re.github.io/ouhboy/images/msf.jpg
description: Metasploit ctf series
---

# stealth

![stealth](https://i.imgur.com/gd7lkVU.png)

[stealth TryHackMe room](https://tryhackme.com/room/stealth)

---

## nmap scans

```bash
PORT      STATE SERVICE       REASON  VERSION
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  http          syn-ack PHP cli server 5.5 or later
8080/tcp  open  http          syn-ack Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
8443/tcp  open  ssl/http      syn-ack Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC

Service Info: OS: Windows
```

---

## checking the site

![site](https://i.imgur.com/uV5DpSl.png)

Checking the site out as described on TryHackMe, we are presented with a web application.

![upload](https://i.imgur.com/JWMZg47.png)

The site only allows uploading **PowerShell scripts**. The goal is to upload a script that gives us a reverse shell.

---

## initial foothold

I generated a PowerShell reverse shell using [revshells.com](http://revshells.com/) and uploaded it to the site. This gave me a callback.

### Disclaimer

Using a basic `nc` listener gives a very limited shell, which is awkward to work with.

![bad shell](https://i.imgur.com/FQKIuhp.png)

A much better shell was obtained using a script from this repo:

* [https://github.com/malw0re/scriptures-](https://github.com/malw0re/scriptures-)

After uploading it, I got a much cleaner shell. While enumerating the filesystem, I found an `encodedflag` file on the Desktop.

Decoding it revealed an interesting message:

![encoded flag](https://i.imgur.com/kNofE1s.png)

Following the hint and checking the webpage again revealed another clue:

![hint](https://i.imgur.com/JqHJOnC.png)

---

## user level flag

Inside the **Documents** directory, there is a folder called `tasks` containing a `log.txt` file. The webpage response hints that we must remove logs to avoid alerting the blue team.

Initially, removing this file did not immediately work. After reviewing `file.ps1`, I noticed a directory related to **XAMPP**.

![xampp](https://i.imgur.com/ZaomI08.png)

Inside the `uploads` directory, another log file was found. After deleting it and refreshing the webpage, the **user flag** appeared.

![user flag](https://i.imgur.com/6C9PKha.png)

![user flag proof](https://i.imgur.com/o4vn183.png)

---

## root level flag

With the user flag obtained, the next step was privilege escalation. Since this is a Windows host, I uploaded a PowerShell privilege enumeration script.

![privesc scan](https://i.imgur.com/q5dzts3.png)

The script (`win-priv-check.ps1`) was downloaded using `Invoke-WebRequest` and executed locally. It revealed that **Apache is running as Administrator**.

![apache admin](https://i.imgur.com/OifDB01.png)

Checking the current privileges:

![privileges](https://i.imgur.com/a72wbxc.png)

Initially, nothing obvious stood out. I then uploaded a malicious PHP web shell (using p0wny shell) and checked privileges again.

![new privs](https://i.imgur.com/A9Yszsw.png)

This time, **SeImpersonatePrivilege** was enabled.

Any process holding this privilege can impersonate tokens obtained via NTLM authentication, which allows SYSTEM-level execution via several *Potato* exploits.

Reference:

* [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)

After testing multiple options, **EfsPotato** successfully escalated privileges to **NT AUTHORITY\SYSTEM**.

![system shell](https://i.imgur.com/F5WGaj8.png)

Attempting to read the admin flag directly resulted in permission issues:

![error](https://i.imgur.com/wDnF2Xy.png)

To work around this, I created a new user, added it to the Administrators group, and logged in via RDP.

![new user](https://i.imgur.com/U29uu8P.png)

Once logged in, I was able to retrieve the **root flag**.

![root flag](https://i.imgur.com/jlALEK2.png)

---

Hope you learned something new ✨

**Author:** Malw0re
