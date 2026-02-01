---
title: Kerberos
date: 2024-07-13 00:00:00
tags:
  - Active-Directory
categories:
  - writeups
top_img: /images/cyberpunk-red.png
cover: /images/kerb.webp

description: Active Directory kerberos
---


## Kerberoasting
The Kerberos protocol defines how clients interact with a network authentication service, clients obtain tickets from the Kerberos Key Distribution Center (KDC) and they submit these tickets to application servers when connections are established. uses port 88 by default and depends on the process of symmetric key cryptography.

*NB* [**kerberos uses tickets to authenticate a user and completely avoids sending passwords across the network**]

![](https://miro.medium.com/v2/resize:fit:720/format:webp/1*J6UHDf5fnbzdKTPawNq3UA.png)

### How Kerb Auth works!
In every Active Directory domain, every domain controller runs a KDC service that provides requests for tickets to kerberos, which is the KRBTGT account in the AD domain.

![1.webp](https://1.bp.blogspot.com/-XHZj0n9oH_g/XrHWMs_s-uI/AAAAAAAAj2E/oxSrDD2wvOEMv-a-nTHhQD2jc-3KMULYgCLcBGAsYHQ/s1600/1.png)

Kerberos uses symmetric cryptography for encryption and decryption.

For explanation purposes, we use three colours to distinguish Hashes:

* **BLUE _KEY**: User NTLM HASH
* **YELLOW_KEY**: Krbtgt NTLM HASH
* **RED_KEY:** Service NTLM HASH

**Step 1:** By sending the request message to KDC, the client initializes communication as:

***KRB_AS_REQ contains the following:***

* The username of the client is to be authenticated.
* *The service **SPN (SERVICE PRINCIPAL NAME)** linked with the Krbtgt account*
* *An encrypted timestamp (Locked with User Hash: Blue Key)*

The entire message is encrypted using the User NTLM hash (**Locked with BLUE KEY**) to authenticate the user and prevent replay attacks.

**Step 2:** The KDC uses a database consisting of Users/Krbtgt/Services hashes to decrypt a message (**Unlock with BLUE KEY**) that authenticates user identification.

Then KDC will generate TGT (Ticket Granting Ticket) for a client that is encrypted using Krbtgt hash (Locked with Yellow Key) & some Encrypted Message using User Hash.

***KRB_AS_REP contains the following:***

* ***Username***
* *Some encrypted data, (Locked with User Hash: Blue Key) that contains:*
* *Session key*
* *The expiration date of TGT*
* ***TGT***, (Locked with Krbtgt Hash: Yellow Key) which contains:
* *Username*
* *Session key*
* *The expiration date of TGT*
* *PAC with user privileges, signed by KDC*

![](https://i0.wp.com/blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEj8cs4DxTHhCqS9yUAa3yOwC8e3ElB50XZ4QyOkWXIEAGssMdjBPNsGVaDz274Z8voKtHNoBHD9qD6PKPvp9KLzdxjUzRtSc_UQ7Jz03v5BHEwhP7wm09K-81SGcv3qTyJ1UDyctCHyDc_PgLZbe4A5GipaqZmDU649RWcNbQtIpM6o6DvKicqXTU5vQA/s16000/2.png?w=640&ssl=1)

**Step 3:** The KRB_TGT will be stored in the Kerberos tray (Memory) of the client machine, as the user already has the KRB_TGT, which is used to identify himself for the TGS request. The client sent a copy of the TGT with the encrypted data to KDC.

***KRB_TGS_REQ*** contains:

* *Encrypted data with the session key*
* *Username*
* *Timestamp*
* *TGT*
* *SPN of requested service e.g. SQL service*

**Step 4:** The KDC receives the KRB_TGS_REQ message and decrypts the message using Krbtgt hash to verify TGT (Unlock using Yellow key), then KDC returns a TGS as KRB_TGS_REP which is encrypted using requested service hash **(Locked with Red Key)** & Some Encrypted Message using User Hash.

***KRB_TGS_REP contains:***

* *Username*
* *Encrypted data with the session key:*
* *Service session key*
* *The expiration date of TGS*
* ***TGS***, (Service Hash: RED Key) which contains:
* *Service session key*
* *Username*
* *The expiration date of TGS*
* *PAC with user privileges, signed by KDC*

![](https://i0.wp.com/blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgEljfKE_fFEoR8kThrILtnjmFwQPfM61p-SZh6Xg64sLUv7GzLgsvk6Ni5YhC8A7ILETnBFHbsa2ldkL6u1mrWGkDStzkFSP9oCeg3cO_9QxjyltM0ZpKm5Jf2oV8lo-IsfR2C7-jAAaRyWTu_Sofn4TV7BhIl0fj5fYPIicSjbScOtyUql25EmTo-Tw/s16000/3.png?w=640&ssl=1)

**Step 5:** The user sends the copy of TGS to the Application Server,

***KRB_AP_REQ contains:***

* *TGS*
* *Encrypted data with the service session key:*
* *Username*
* *Timestamp, to avoid replay attacks*

**Step 6:** The application attempts to decrypt the message using its NTLM hash and to verify the PAC from KDC to identify user Privilege which is an optional case.

**Step 7:** KDC verifies PAC (Optional)

**Step 8:** Allow the user to access the service for a specific time.

## SPNs
The Service Principal Name (SPN) is a unique identifier for a service instance. Active Directory Domain Services and Windows provide support for Service Principal Names (SPNs), which are key components of the Kerberos mechanism through which a client authenticates a service.

**Important Points**

* If you install multiple instances of a service on computers throughout a forest, each instance must have its SPN.
* Before the Kerberos authentication service can use an SPN to authenticate a service, the SPN must be registered on the account.
* A given SPN can be registered on only one account.
* An SPN must be unique in the forest in which it is registered.
* If it is not unique, authentication will fail.

### SPNS syntax
**The SPN syntax has four elements**

![](https://i0.wp.com/blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEh5w4iPbIsIxS5VNUzD13_nOXg-0AbmhtwdJWBUqi4keSFbajcnh5Bgqro7FOj686VwDTBbtu0oYjZbBGRyRWxUHy8EAJp8jmUQpDBymwTWzE_9RIpwOkK2Ul6bxIbDZSwHYhknzECBwjBEd4VU5HyMeCciosGRPfcjbaN62fLe6WPiArdLqlHrpGMKOQ/s16000/5.png?w=640&ssl=1)

### Type of SPN
* Host-based SPNs which is associated with the computer account in AD, it is randomly generated 128-character long password which is changed every 30 days; hence it is no use in Kerberoasting attacks
* SPNs that have been associated with a domain user account where NTLM hash will be used.

### Linux Perspective
#### Attack Procedure.
Depending on your positioning a network, Kerberos attacks can be performed in multiple ways.

* From a non-domain joined Linux host using valid domain user credentials.
* From a domain-joined Linux host as root after retrieving the keytab file.
* From a domain-joined Windows, the host is authenticated as a domain user.
* From a domain-joined Windows host with a shell in the context of a domain account.
* As SYSTEM on a domain-joined Windows host.
* From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) /netonly.

#### Tools.
Some tools can be utilized to perform the attack.

* Impacket’s [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
* A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
* From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

**REMEMBER!!!**

Obtaining a TGS ticket via kerberoasting does not guarantee a set of valid credentials and the ticket still must be cracked offline to obtain the cleartext password.

TGS tickets generally take longer to crack than other formats such as NTLM hashes, so often, unless a weak password is set, it can be difficult or impossible to obtain the cleartext using s standard cracking rig.

#### The efficiency of Attack
While it can be a great way to move lateral or escalate privileges in a domain kerberoasting and the presence of SPNs does not guarantee us any level of access.

We might be in an environment where we crack a TGS ticket and obtain Domain Admin access straightway or obtain credentials that help us move down the path to domain compromise. Other times we may perform the attack and retrieve many TGS tickets, some of which we can crack, but none of the ones that crack are for privileged users, and the attack does not gain us any additional access.

**N/B -** When writing a report this finding is termed as high-risk in the first two cases. Third case we may Kerberos and end up unable to crack a single TGS ticket even after mad days of cracking attempts with Hashcat. This would be dropped as a medium-risk issue to make the client aware of the risk of SPNs in the domain.

**REMEMBER!!!**

A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.

#### GetUserSPNs.py
**Listing SPN Accounts.**

`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend`

#### Requesting all TGS tickets.**
Later on, we can pull all TGS tickets for offline processing using the **-request** flag. The TGS tickets will be output in a format that can be readily provided to Hashcat or Johnny for offline password-cracking attempts.

`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request`

#### Requesting a Single TGS Ticket.
Wte can also be more targeted and request just the TGS ticket for a specific account. Let’s try requesting one for just the required account.

`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user`

With this ticket in hand, we could attempt, to crack the password offline, if successful we may end up with Domain Admin Rights.

Saving the Ticket o facilitate offline cracking, it is always good to use the `-outputfile` flag to write the TGS tickets to a file that can then be run using Hashcat on our attack system or moved to a GPU cracking rig.

`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs`

### Windows Perspective
Kerberoasting - Semi-Manual Method.

#### Enumerating SPNs with setspn.exe
`setspn.exe -Q */*` running the command you’ll notice many different SPNs returned for the various hosts in the domain.

#### Retrieving All Tickets using setspn.exe
`setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }`

The above command combines the previous command with `setspn.exe` to request tickets for all accounts with SPNs set.

Using **Powershell** we can request TGS tickets for an account in the shell and load them into memory, once they are loaded into memory we can extract them using **Mimkatz.**

#### Targeting a Single User**************
```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"