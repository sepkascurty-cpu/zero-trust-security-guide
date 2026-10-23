# Zero Trust Quiz 🧠

5 questions. Answers are collapsed — no peeking before you commit to an answer!

---

### 1. What is the core assumption that separates Zero Trust from the perimeter model?

A) Firewalls are fast enough to inspect all traffic
B) The network may already be compromised, so every request must be verified
C) VPNs should be replaced with faster VPNs
D) Only external attackers matter

<details>
<summary>Answer</summary>

**B.** Zero Trust assumes breach: trust is never implied by network location. Every request is evaluated on identity, device posture, and context.

</details>

---

### 2. Which AWS control enforces a rule that even the account root user cannot bypass?

A) IAM permission boundary
B) Security Group
C) Service Control Policy (SCP) with an explicit Deny
D) AWS Config rule

<details>
<summary>Answer</summary>

**C.** SCP Deny statements apply organization-wide and cannot be overridden by any principal in the account — including root. That's why they're the purest "guardrail" implementation of least privilege.

</details>

---

### 3. A Kubernetes namespace has a `default-deny-all` NetworkPolicy (Ingress + Egress). A pod's DNS lookups suddenly fail. What did you forget?

A) To allow egress to kube-dns on port 53
B) To label the pod with `app: dns`
C) To restart CoreDNS
D) To open ingress on port 53

<details>
<summary>Answer</summary>

**A.** Default-deny Egress blocks *everything*, including DNS. You must explicitly allow egress to kube-dns (UDP/TCP port 53) — the single most common micro-segmentation gotcha. (See the example at the bottom of `zero-trust/main.tf`.)

</details>

---

### 4. Why is SMS-based MFA considered weak in a Zero Trust design, and what should replace it?

A) SMS is too slow; replace with email OTP
B) SMS is vulnerable to SIM-swapping and phishing; replace with phishing-resistant MFA like FIDO2/WebAuthn
C) SMS costs too much; replace with push notifications only
D) SMS doesn't work with SSO; replace with static passwords

<details>
<summary>Answer</summary>

**B.** SIM-swapping and adversary-in-the-middle phishing defeat SMS codes. Zero Trust wants *strong, phishing-resistant* identity proof — FIDO2 security keys or passkeys (WebAuthn).

</details>

---

### 5. "We bought a Zero Trust product, so we're Zero Trust compliant now." What's wrong with this statement?

A) Nothing — that's exactly how it works
B) Zero Trust is an architecture of identity, segmentation, and continuous verification — no single product delivers it; buying a tool without the architecture is theater
C) Zero Trust products don't exist
D) Compliance doesn't apply to security models

<details>
<summary>Answer</summary>

**B.** Zero Trust is a set of principles implemented across identity, devices, networks, and workloads. A product can *help* (e.g. a ZTNA broker), but without the architecture — least privilege, micro-segmentation, continuous verification — it's just marketing.

</details>

---

**Score:** 5/5 — you're ready to segment production. 3–4 — re-read the pillars. 0–2 — start with "Why Perimeter Security Failed" again. No shame in the loop. 🔁
