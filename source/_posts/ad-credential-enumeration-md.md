---
title: AD CRED ENUM
date: 2023-08-09 00:00:00
updated: 2025-09-15 01:58:43
tags:
  - Active-Directory
categories:
  - research
top_img: /images/cyberpunk-red.png
cover: /images/darkbasin.jpg
description: Active Directory credential enumeration
---

![](https://miro.medium.com/v2/resize:fit:750/0*Kz1iA9w7Ciywdu1A.jpg)

## Credential Enumeration
After acquiring a foothold, you must dig deeper using the low-privilege domain user credentials. Information to be interested in when enumerating:

* Domain users
* Computer Attributes
* group membership
* Group Policy Objects
* Permissions
* ACLs
* Trusts

Most of these tools will not work without domain users’ credentials at any permission level. So at a minimum, you need to have acquired a user’s cleartext password, NTLM password hash or SYSTEM access on a domain-joined host.

## CrackMapExec
This tool can be used to assess AD environments, where it utilizes packages from the impacket and powersploit toolkit to perform its functions.

### Domain UserEnum
When enumerating you need to point CME to the Domain Controller. CME provides a **badPwdCount** attribute which is helpful when performing targeted pass spraying to avoid locking out accounts.

`sudo crackmapexec smb xx-domain-ip-xx -u xxxxxxxx -p xxxxx --users`

### Domain Group Enum
We can obtain a complete listing of domain groups. Take note of key groups like `Administrators`, `Domain Admins`, and `Executives`.

`sudo crackmapexec smb xx-domain-ip-xx -u xxxxxxxx -p xxxxx --groups`

## Smbmap
A tool for enumerating SMB shares from a Linux environment to list shares, permissions, and content.

### recursive list Dirs in Shares
`smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only`

## RpcClient
Used to enumerate, add, change and even remove objects from AD.

### Enumeration
A Relative Identifier (RID) is combined with a SID to make a unique value representing an object. Built-in admin accounts for domains will typically have a RID of **500** or **0x1f4**.

## Impacket-Toolkit
A versatile toolkit used to interact with and exploit Windows protocols using Python.

### Psexec.py
Provides a shell as SYSTEM on the victim host by creating a remote service via RPC.

### windapsearch
A Python script to enumerate users, groups, and computers utilizing LDAP queries.

`python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da`

## BloodHound
An auditing tool that creates a GUI representation of "attack paths" within Active Directory.

## ActiveDirectory Powershell Modules
Cmdlets used for enumerating AD environments.

* `Get-ADDomain`: Prints domain SID and functional level.
* `Get-ADTrust -Filter *`: Prints domain trust relationships.
* `Get-ADGroupMember -Identity "Backup Operators"`: Lists group membership.

## Powerview
Identifies where users are logged in and hunts for file shares, passwords, and ACLs.

| Command | Description |
| --- | --- |
| Get-DomainUser | Returns all users or specific user objects |
| Get-DomainGroupMember | Returns members of a specific domain group |
| Find-LocalAdminAccess | Finds machines where current user has admin access |
| Get-DomainTrust | Returns domain trusts |

## Shares
### Snaffler
Works by obtaining a list of hosts and enumerating shares for sensitive data or credentials.

## Living off the Land
Using native Windows tools is a stealthy approach that creates fewer log entries for defenders to detect.

| Command | Result |
| --- | --- |
| hostname | Prints the PC’s Name |
| ipconfig /all | Prints out network configurations |
| set %logonserver% | Prints name of the Domain controller |

## OPSec Tactics
Defender visibility can be avoided by calling PowerShell version 2.0 or older, as event logging was introduced in version 3.0.

### Checking Defenses
* Firewall check: `netsh advfirewall show allprofiles`
* Defender check: `sc query windefend`

## WMI (Windows Management Instrumentation)
A scripting engine used to retrieve info and run admin tasks.

`wmic qfe get Caption,Description,HotFixID,InstalledOn`

## Net Commands
Useful for querying the localhost and remote hosts.

`net group "Domain Admins" /domain`

**Tip:** Use `net1` instead of `net` to potentially bypass basic command monitoring.

## Dsquery
A command-line tool found at `C:\Windows\System32\dsquery.dll` used to find AD objects.