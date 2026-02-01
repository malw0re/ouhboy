---
title: MSF CTF
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

# Metasploit ctf I (*easy*)

### CTF Scenario:
* This lab is dedicated to you! No other users are on this network :)
* Once you start the lab, you will have access to a Kali terminal based instance. This machine has an interface with IP address 192.X.Y.Z.
* The lab has two target machines which should be located on the same subnet i.e. 192.X.Y.0/24
* The target systems most of times, belong to “admin” or “root” user.
* Do not attack the gateway located at IP address 192.X.Y.1
* You can use all tools installed in Kali to complete this lab.

## Flags:
* This lab has only 1 Flag to be collected.
* The Flag can be identified either by the strings flag, flagX, FLAG, FLAGX.
* The Flag can either be a normal string or a 32-character random Hex string.

## Recon
checking our network interfaces, with `ip a s` this is a command used to display info about the network interfaces on the system.

![](https://i.imgur.com/Q3nW1a4.png)

Having identified our target `target-1`, & `target-2` , our aim is to exploit the two boxes, so running an nmap scan we see `target-1` is running `rmiregistry` on port 1909 and `target-2` is running ssh.

![](https://i.imgur.com/Vzu6BCd.png)

What is ***rmiregistry***? it’s a tool in Java used for Remote Method Invocation to manage and look up remote objects on a network, *RMI* in java allows objects in one Java Virtual Machine to invoke methods on objects residing in another JVM, another remote machine.
This provides a way for Java applications to communicate and interact across a network. [[Read More](https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/index.html)]

## metasploit
since it’s a metasploit ctf we need to check out for some exploit.

We find a module that take advantage of the default configuration of the RMI registry and RMI Activation services, which allow loading classes from any remote (HTTP) URL.

As it invokes a method in the RMI Distributed Garbage Collector which is available via every RMI endpoint, it can be used against both rmiregistry and rmid, and against most other (custom) RMI endpoints as well. Note that it does not work against Java Management Extension (JMX) ports since those do not support remote class loading, unless another RMI endpoint is active in the same Java process.

RMI method calls do not support or require any sort of authentication.

## exploit
So, loading up everything on metasploit, running the module we get a shell back

![](https://i.imgur.com/Le8fCAn.png)

stabilizing our shell we go to the home directory under the folder alice there is some ssh keys that we can use and login with since we are already root.

![](https://i.imgur.com/LUcKnZZ.png)

so, having known where the ssh keys are we can background our sessions and use the ssh_creds metasploit module.

## flag.
the ssh_creds metasploit module, it will collect the contents of all users’ .ssh directories on the targeted machine.

![](https://i.imgur.com/Feds9zY.png)

After which we can use the ssh_login module to login into the machine *target-2*, we are using the login_pubkey cause of the public key we got on the alice folder.

![](https://i.imgur.com/8bo6jEO.png)

**N|B**

I set the rhost to the machine that we are targeting *target-2* which is the ip with the *.4*.

Checking our sessions we see that we have a new session created and we got the flag.

![](https://i.imgur.com/vsZZTmU.png)

![](https://i.imgur.com/7rV9TRB.png)
![](https://i.imgur.com/BDHEMIo.png)