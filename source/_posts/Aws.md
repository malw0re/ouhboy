---
title: AWS Security
date: 2026-01-11 12:44:04
tags:
  - AWS
  - CloudSecurity
  - Cloud
categories: research
keywords: 'Cloud, CloudSecurity AWS'
top_img: /images/cyberpunk-red.png
cover: /images/aws.png

---

# AWS Security

[](https://images.coursestack.com/e0cb94d8-532a-4658-bfdd-5400224f2414/62006482-80a6-4d8b-bcbd-26370aa870c4)

Before we do anything else, let's start at the absolute beginning with Identity.

## **AWS Identity Basics**

### **Account – Your Primary Security Boundary**

An **AWS account** is an isolated container for resources, billing, and identity roots. Nothing inside one account is reachable from another, unless you create an explicit bridge (VPC peering, cross‑account role, etc.).

An account is where you will be able to run infrastructure like EC2s, Lambdas, Containers DBs, etc. It's always needed to create at least 1 AWS account in order to spawn infrastructure in AWS.

*Security best practice:* Create separate accounts for different environments and purposes. For example, create an account for *dev*, *staging*, *prod*, *logging*, and *security* to keep the blast radii small.

### **Organization – Governance at Scale**

An **AWS Organization** groups multiple AWS accounts under the first AWS account you created (usually called a **management account)**. It lets you apply policies as guardrails like Service Control Policies (SCPs), consolidate billing, and centrally enable services like GuardDuty.

*Security best practice:* If an attacker owns the management account, they can assume **OrganizationAccountAccessRole** in every child account—an instant fleet takeover. Therefore, it's highly recommended to only use the first AWS account a company creates to create other companies and setup policies for the organization. Don't use it to run infrastructure or store data to reduce risks.

### **User – Long‑Lived Human Credential**

An **IAM user** represents a person or (rarely) an app that needs permanent credentials. Each user can have a console password and up to two access‑key pairs. Passwords and access‑key pairs should be rotated every once in a while.

*Security best practice:* Issue as few users as possible (use AWS Identity Center instead of IAM to create users), enforce MFA, tag them for ownership, and don't allow the generation of access‑keys to IAM users if possible.

### **Role – Temporary, Scoped Identity**

An **IAM role** has no long‑term credentials. It’s assumed by users, AWS services, or external identities to receive short‑lived **STS tokens**. Roles are the default way to grant a workload or person just‑in‑time access or to hop between accounts.

*Cross‑account role example:* Your CI pipeline in the *build* account assumes `arn:aws:iam::<prod‑id>:role/Deploy` for only the minutes a deployment runs.

### **Policy – Permissions DNA**

A **policy** is a JSON document that *allows* or *denies* specific actions on specific resources, optionally under conditions (e.g., IP, MFA). **Policies can include wildcards (`*`) to match multiple actions or resources—for instance, `"s3:Get*"` covers every read‑style operation on S3 objects.**

Policies come in three flavors:

1. **AWS‑managed** – maintained by AWS (often overly broad, e.g., `AdministratorAccess`).
2. **Customer‑managed** – reusable policies you craft.
3. **Inline** – embedded directly in a user, role, or group (cannot be reused in other principals).

Least privilege lives or dies here—review policies regularly and prune `*` patterns wherever possible.

**Tip:** Keep the management account for **creation and governance only**; deploy workloads in member accounts.

---

[](https://images.coursestack.com/e0cb94d8-532a-4658-bfdd-5400224f2414/c8e4ffc8-8d80-41af-91bb-9eb93b04b561)

## **Over‑Privilege: Cloud Enemy #1**

“So‑and‑so just **added** `AdministratorAccess` so we could test.” That single sentence explains how most cloud breaches begin. IAM is **complex**, deadlines are short, and the impact of over‑granting rights is invisible—until the day it isn’t. Here are the typical pathways that lead well‑meaning engineers to over‑privilege others at the outset:

- **Copy‑pasted tutorials** – Many AWS “getting‑started” guides and Stack Overflow answers use  actions for brevity. Teams adopt these JSON snippets unchanged and move on.
- **Third‑party quick‑starts** – SaaS vendors often ship CloudFormation templates that request full admin access so their product “just works.” Security reviews are skipped under go‑live pressure.
- **Role sprawl during incidents** – When production is burning, on‑call staff add broad policies to unblock themselves, but the temporary fix rarely gets rolled back.
- **AWS managed policies** – Default AWS‑managed policies such as `PowerUserAccess` or `AmazonEC2FullAccess` pack far more rights than most workloads need. Attaching them may feel “supported” but silently grants privilege far beyond requirements.
- **Inherited legacy accounts** – New hires receive keys from a previous admin and no one knows which services still rely on which permissions, so the safest (but least secure) bet is to keep everything.
- **Lack of fine‑grained understanding** – IAM’s JSON syntax, condition keys, and service‑specific nuances intimidate newcomers. Granting `AdministratorAccess` feels simpler than composing a least‑privilege doc.

Over‑privilege turns every credential leak or phishing email **into** a full‑account takeover. Continuous hygiene matters: run tools like [**`aws_iam_review`**](https://github.com/carlospolop/aws_iam_review) or AWS **Access Analyzer** weekly to flag rights that were *never* used or are *dangerous by design*. The goal is a living permissions baseline—anything outside it triggers a security review.

---

[](https://images.coursestack.com/e0cb94d8-532a-4658-bfdd-5400224f2414/6fa823f8-ab99-4259-b7d6-79e4b7c9794e)

## **Three Practical Privilege Escalation Paths**

### **1. AttachUserPolicy**

**Minimal permission:** `iam:AttachUserPolicy`

**Goal:** Grant yourself `AdministratorAccess` by attaching a managed policy to your own user.

**Attack breakdown**

1. **Discover your user ARN** – `aws iam get-user` confirms the identity you can manipulate. *You must target the exact principal you control.*
2. **Refresh credentials** – re‑authenticate or generate fresh keys so AWS re‑evaluates your permission set. *You now wield unrestricted power across the account.*

[HackTricks Reference](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-iam-privesc.html)

---

### **2. PassRole + RunInstances**

**Minimal permissions:** `iam:PassRole`, `ec2:RunInstances`, and some others...

**Goal:** Spawn an EC2 instance that inherits a powerful role and steal its temporary session tokens.

**What is EC2?** Amazon Elastic Compute Cloud—on‑demand virtual servers you can launch and control like VMs.

**Attack breakdown**

1. **Enumerate pass‑able roles** – `aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==\`ec2.amazonaws.com`]]'` lists roles whose trust policy allows EC2. *Only these can be passed during instance launch.*
2. **Choose a high‑privilege role** – pick one bound to `AdministratorAccess` or similar rights. *The stronger the role, the bigger the blast radius.*
    1. **Attach the admin policy** – `aws iam attach-user-policy --user-name <name> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` stores a policy/identity link object. *This adds every admin right in one API call.*
3. **Launch an EC2 with the role** – `aws ec2 run-instances --iam-instance-profile Name=<roleName> ...` binds the instance profile. *The Instance Metadata Service (IMDS) will serve STS creds for that role to the VM.*
4. **Harvest credentials** – inside the VM, run `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<roleName>` to obtain JSON creds. *Use them from your workstation; they’re equivalent to **`sts:AssumeRole`** without MFA.*

This is a very common privilege escalation attack pattern in cloud environment where an attacker uses a cloud service that can run some code defined by the attack and attaches to the service a role with more privileges so the executed token steals the token of the role, effectively escalating privileges to the role.

[HackTricks Reference](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc.html)

---

### **3. PutKeyPolicy Overreach (KMS)**

**Resource policies:** KMS keys—and several other AWS services like S3, SQS, SNS, Lambda and Secrets Manager—support **resource‑based policies**. These JSON documents live *on the resource itself*, not on IAM identities, and they are evaluated in addition to IAM permissions. If you can modify a resource policy you can sidestep IAM entirely, granting new principals (or wildcards) access that IAM would otherwise forbid.

**Minimal permissions:** `kms:ListKeys`, `kms:PutKeyPolicy` *(plus **`kms:ListKeyPolicies`**, **`kms:GetKeyPolicy`** for reconnaissance)*

**Goal:** Rewrite a KMS key’s policy so you—or **everyone**—get full `kms:*` control, letting you decrypt data, create rogue grants, or lock out legitimate owners.

**Attack breakdown**

1. **Enumerate keys** – `aws kms list-keys --query 'Keys[*].KeyId'` reveals every Customer Master Key (CMK) ID. *Chooses the asset to hijack.*
2. **Back up current policy** – `aws kms get-key-policy --key-id <KeyId> --policy-name default` (if allowed) saves the JSON. *Useful for later restoration or careful edits.*
3. **Craft permissive policy** – create `evil.json` that adds your principal with `"Action":"kms:*"` on the key, or sets `"Principal":"*"` for total takeover. *Defines your escalated rights.*
4. **Upload new policy** – `aws kms put-key-policy --key-id <KeyId> --policy-name default --policy file://evil.json` overwrites the existing document. *You are now a key admin.*
5. **Exploit access** – decrypt Secrets Manager ciphertexts, re‑encrypt data with keys only you control, or create grants for other attacker principals. *Breaks data‑at‑rest guarantees across S3, RDS, EBS, etc.*

[HackTricks Reference](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-kms-privesc.html)

---

## **Other High-Frequency Cloud Weaknesses**

### **1. Leaked keys & secrets**

GitGuardian’s 2024 *State of Secrets Sprawl* detected **12.7 million** new secrets in public GitHub commits—many of them AWS keys ([gitguardian.com](https://www.gitguardian.com/state-of-secrets-sprawl-report-2024?utm_source=chatgpt.com)). Independent researchers found attackers start abusing freshly leaked keys within minutes ([helpnetsecurity.com](https://www.helpnetsecurity.com/2024/12/02/revoke-exposed-aws-keys/?utm_source=chatgpt.com)). Real‑world examples include Uber’s 2022 breach triggered by a hard‑coded admin credential in a PowerShell script ([medium.com](https://medium.com/%40tolubanji/hardcoded-secrets-the-unseen-security-risk-lurking-in-your-code-102396345115?utm_source=chatgpt.com)) and Toyota accidentally publishing long‑lived access tokens to GitHub for five years ([blog.gitguardian.com](https://blog.gitguardian.com/toyota-accidently-exposed-a-secret-key-publicly-on-github-for-five-years/?utm_source=chatgpt.com)).

**Mitigation:** enable secret scanning in CI, rotate keys frequently, prefer roles over long‑lived keys, and block public CI artifacts that contain `.aws/` credential files.

### **2. Public storage & network exposure**

Public data stores (S3 buckets, EBS snapshots, RDS instances) and overly permissive network paths (security groups allowing `0.0.0.0/0`, NodePorts, or public load balancers) share the same root problem: **resources are reachable from the internet when they shouldn’t be**. Capital One’s breach blended an over‑permissive WAF role with a public S3 bucket ([darkreading.com](https://www.darkreading.com/cyberattacks-data-breaches/capital-one-attacker-exploited-misconfigured-aws-databases?utm_source=chatgpt.com)); Pegasus Airlines exposed 6.5 TB of flight data in an S3 bucket ([cshub.com](https://www.cshub.com/attacks/news/iotw-turkish-based-airline-leaves-65-tb-of-sensitive-data-exposed?utm_source=chatgpt.com)); and Accenture left four S3 buckets world‑readable, leaking internal credentials ([upguard.com](https://www.upguard.com/breaches/cloud-leak-accenture?utm_source=chatgpt.com)).

**Mitigation:** enforce private subnets and VPC endpoints for storage services, apply security‑group baselines that deny `0.0.0.0/0` except via a bastion or WAF‑protected load balancer, and run continuous exposure scans with tools like ScoutSuite, Prowler, or CloudMapper.

### **3. Misconfigured cross‑account trust**

Trust paths that allow external AWS accounts—or worse, the entire internet via `"Principal":"*"`—become silent back doors. Twilio’s 2022 incident began with SMS‑phishing of employee credentials, then leveraged trusted roles to pivot to customer data ([wired.com](https://www.wired.com/story/twilio-breach-phishing-supply-chain-attacks?utm_source=chatgpt.com)). Forgotten vendor roles or old CI/CD integrations have caused similar lateral movement in red‑team exercises.

**Mitigation:** enable IAM **Access Analyzer** to detect unintended public or cross‑account access, review trust policies quarterly, and require external IDs plus condition keys such as `aws:PrincipalOrgID` when sharing roles with suppliers. Public storage & network exposure

Public data stores (S3 buckets, EBS snapshots, RDS instances) and overly permissive network paths (security groups allowing `0.0.0.0/0`, NodePorts, or public load balancers) share the same root problem: **resources are reachable from the internet when they shouldn’t be**. Capital One’s 2019 breach mixed an over‑permissive IAM role with an S3 bucket policy, while hundreds of companies have leaked customer databases by exposing MongoDB, Redis, or Elasticsearch on public IPs.

**Mitigation:** enforce private subnets and VPC endpoints for storage services, apply security‑group baselines that deny `0.0.0.0/0` except via a bastion or WAF‑protected load balancer, and run continuous exposure scans with tools like ScoutSuite, Prowler, or CloudMapper.

### **3. Misconfigured cross‑account trust**

Trust relationships that allow external AWS accounts—or worse, the entire internet via `"Principal":"*"` in an IAM trust policy—can hand attackers a permanent back door even if your own IAM permissions look tight. Red‑team assessments often uncover forgotten vendor roles or legacy OAuth integrations that now let a compromised partner pivot into your environment.

**Mitigation:** enable IAM **Access Analyzer** to detect unintended public or cross‑account access, review trust policies quarterly, and require external IDs plus condition keys such as `aws:PrincipalOrgID` when sharing roles with suppliers.

## **What about persistence?**

When an attacker gains access, the next objective is to **remain in your environment without tripping alarms**. In AWS, persistence can be established through identities (IAM), infrastructure (EC2 user‑data, container images), or serverless hooks (EventBridge, Lambda). Common, noisy tricks include:

- **Creating a new IAM user + access keys** hidden among legitimate accounts.
- **Adding their own SSH key** to EC2 instance metadata or User Data.
- **Scheduling a Lambda or Step Functions task** to re‑deploy backdoors daily.
- **Planting malicious versioned objects** in S3 or CodeCommit that CI/CD pipelines auto‑pull.

However, those actions are usually very noisy. Below we explore a stealthier method that abuses Lambda layers—a resource most teams overlook during audits.

### **Stealthy Persistence: Lambda Layer Backdoor**

AWS Lambda **layers** let you **inject shared code** into one or many functions. If an attacker controls `lambda:PublishLayerVersion` and `lambda:UpdateFunctionConfiguration`, they achieve **pre‑execution code injection**: every cold start loads their module *before* the legitimate handler, enabling secret scraping, SDK monkey‑patching, or reverse shells—all **without altering the function code visible in the console**. Layers are account‑global, region‑scoped, and referenced only by ARN plus version, so malicious variants hide in plain sight and survive CI redeploys.

### **Attack recipe**

1. Craft a layer containing malicious Python (`sitecustomize.py`) or Node.js (`index.js`) that executes on import.
2. Upload with `lambda:PublishLayerVersion` (creates `arn:aws:lambda:region:acct-id:layer:evil:1`).
3. Attach the layer to a target function via `lambda:UpdateFunctionConfiguration`. This does **not** modify the function code itself—auditors reviewing the inline handler will see nothing.
4. Each invocation of the function automatically imports the malicious layer, exfiltrating secrets or opening a reverse shell.
5. The attacker can later push a new version (`lambda:PublishLayerVersion` again) and silently bump the function to the new ARN, persisting across blue‑green deployments.

### **Why it evades detection**

- CloudTrail logs show `UpdateFunctionConfiguration` but security teams rarely inspect the `Layers` field.
- The layer code executes in‑process, so there are no unusual outbound API calls unless the payload triggers them.
- Layers can be shared; a single rogue layer can infect dozens of functions across multiple teams.

---

## **Defense & Monitoring Strategies**

Securing AWS is not a one‑time checklist—it is continuous **hardening + monitoring** on every account.

### **1. Harden every account in isolation**

- **Least privilege IAM** – prune unused permissions, rely on roles not users, and enforce MFA.
- **Service Control Policies (SCPs)** – create deny‑all guardrails (e.g., block `s3:PutBucketPolicy` that makes buckets public).
- **Secure defaults** – force EBS encryption by default, disable public AMIs, require IMDSv2 on EC2.

### **2. Eliminate misconfigurations early**

- **IaC scanning** – integrate tfsec, cfn‑nag, or Checkov in CI to fail builds containing risky patterns.
- **AWS Config rules** – require S3 versioning, RDS encryption, no open Security Groups, etc.
- **Stack sets & baselines** – deploy golden VPCs, guard S3 buckets with Block Public Access, and set mandatory tags.

### **3. Restrict external trust**

- **Don’t grant wildcards** – avoid `"Principal":"*"` in trust policies.
- Use ExternalId + **`aws:PrincipalOrgID`** when letting vendors assume roles.
- **Rotate credentials** or disable trust paths when contracts end.

### **4. Test the posture constantly**

- **Automated scanners** – run Prowler, ScoutSuite, or AWS Trusted Advisor weekly.
- **Periodic pentests & red teaming** – simulate adversaries, validate alerting, and measure time‑to‑detection.
- **Chaos engineering** – sandbox kill‑switches (e.g., revoke `AdministratorAccess` in dev) to prove least‑privilege.

### **5. Monitor for malicious actions**

- **Organization‑wide CloudTrail** to a dedicated logging account with S3 Bucket Logging and MFA delete.
- **GuardDuty** for anomaly + threat intel detection (crypto‑miners, backdoor IPs, credential exfil).
- **Security Hub** to aggregate findings; auto‑remediate with EventBridge + Lambda (e.g., disable keys leaked to GitHub).
- **CloudWatch & EventBridge rules** – alert on risky APIs: `iam:CreateAccessKey`, `kms:PutKeyPolicy`, `lambda:PublishLayerVersion`.
- **Centralized SIEM** to correlate AWS logs with endpoint and SaaS telemetry.

# **Wrap-Up**

## Key Takeaways

1. Follow the least privilege principle from day one.
2. Why you should split dev, test, and prod into different accounts.
3. Lock down the root / management account with MFA — and never use it!
4. Continuously harden all AWS accounts and have alerts to detect malicious actions.
5. Inspect less‑obvious spots like Lambda layers and snapshots.