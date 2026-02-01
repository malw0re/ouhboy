---
title: ACL AD
date: 2024-01-04 00:00:00
updated: 2025-09-14 23:00:49
tags:
  - Active-Directory
  - access control list
categories:
  - research
top_img: /images/cyberpunk-red.png
cover: /images/access.jpg
description: Access Control List
---

## Active Directory ACLs
Access Control Lists (ACLs) define the permissions for objects within Active Directory.

### Key Concepts
* **ACE (Access Control Entry)**: An individual permission entry within an ACL.
* **DACL (Discretionary ACL)**: Defines who has what access to an object.
* **SACL (System ACL)**: Used for auditing access attempts.

### Security Risks
Misconfigured ACLs can lead to privilege escalation, such as "GenericAll" or "WriteDacl" permissions granted to low-privilege users.