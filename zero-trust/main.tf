# Zero Trust on AWS — Terraform
# Pillar-by-pillar building blocks: guardrails (SCP), identity-first access
# (Verified Access), least-privilege IAM, and K8s micro-segmentation.
#
# NOTE: some resources (org SCPs, Verified Access) need an AWS Organization
# and a verified identity provider. Start in a sandbox account first.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "org_root_id" {
  description = "AWS Organizations root ID (e.g. r-xxxx)"
  type        = string
}

variable "trusted_idp_arn" {
  description = "ARN of the OIDC/user-pool trust policy for Verified Access"
  type        = string
}

# ─── Pillar 3: Least privilege as an org-wide guardrail ─────────────────────
# Nobody — not even the account root user — can bypass an SCP "Deny".
# Rule #1 of Zero Trust: default-deny, then open only what is proven necessary.

resource "aws_organizations_policy" "deny_without_mfa" {
  name    = "ZeroTrust-DenyWithoutMFA"
  type    = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyAllActionsWithoutMFA"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_without_mfa" {
  policy_id = aws_organizations_policy.deny_without_mfa.id
  target_id = var.org_root_id
}

# Deny leaving resources wide open — least privilege at the data plane too.
resource "aws_organizations_policy" "deny_public_exposure" {
  name    = "ZeroTrust-DenyPublicExposure"
  type    = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyPublicS3ACLs"
        Effect   = "Deny"
        Action   = ["s3:PutBucketAcl", "s3:PutObjectAcl"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = ["public-read", "public-read-write", "authenticated-read"]
          }
        }
      },
      {
        Sid      = "DenyOpenSecurityGroups"
        Effect   = "Deny"
        Action   = ["ec2:AuthorizeSecurityGroupIngress"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Cidr" = "0.0.0.0/0" }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_public_exposure" {
  policy_id = aws_organizations_policy.deny_public_exposure.id
  target_id = var.org_root_id
}

# ─── Pillar 1+2: Identity-aware access WITHOUT a VPN ───────────────────────
# AWS Verified Access = Zero Trust Network Access: every app request is
# evaluated against identity + device posture. No network-level trust.

resource "aws_verifiedaccess_trust_provider" "idp" {
  description         = "Corporate IdP for Zero Trust app access"
  policy_reference_name = "corp-idp"
  trust_provider_type = "user"
  user_trust_provider_type = "oidc"
  oidc_options {
    issuer                = "https://idp.example.com"
    authorization_endpoint = "https://idp.example.com/authorize"
    token_endpoint        = "https://idp.example.com/token"
    client_id             = "verified-access-client"
    client_secret         = var.trusted_idp_arn # reference via Secrets Manager in prod
    scope                 = "openid email profile"
  }
}

resource "aws_verifiedaccess_instance" "ztna" {
  description = "Zero Trust app access — no VPN required"
}

resource "aws_verifiedaccess_group" "internal_apps" {
  verifiedaccess_instance_id = aws_verifiedaccess_instance.ztna.id
  description                = "Policy: managed device + engineering group only"

  # Cedar policy: identity AND device posture must pass, per request.
  policy_document = <<-EOT
    permit(
      principal,
      action,
      resource
    )
    when {
      // identity: must belong to the engineering group
      principal has "groups" && principal.groups.contains("engineering")
      // device: managed, patched, disk-encrypted (from device certificate)
      && context.device has "managed" && context.device.managed == true
      && context.device has "diskEncryption" && context.device.diskEncryption == true
    };
  EOT
}

# ─── Pillar 1: Least-privilege IAM role (no static keys, 1h max sessions) ──

data "aws_iam_policy_document" "assume_with_mfa" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.me.account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
    condition {
      test     = "NumericLessThanEquals"
      variable = "aws:MultiFactorAuthAge"
      values   = ["3600"] # re-verify MFA every hour: continuous verification
    }
  }
}

data "aws_caller_identity" "me" {}

resource "aws_iam_role" "zero_trust_devops" {
  name                 = "ZeroTrust-DevOps"
  max_session_duration = 3600 # short-lived sessions only
  assume_role_policy   = data.aws_iam_policy_document.assume_with_mfa.json
}

# Pillar 3 in action: the role can ONLY do what the job needs — nothing more.
resource "aws_iam_role_policy" "deploy_limited" {
  name = "DeployLimited"
  role = aws_iam_role.zero_trust_devops.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DeployToEcsOnly"
        Effect   = "Allow"
        Action   = ["ecs:UpdateService", "ecs:DescribeServices"]
        Resource = "arn:aws:ecs:*:${data.aws_caller_identity.me.account_id}:service/prod/*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = "ap-southeast-1" }
        }
      }
    ]
  })
}

# ─── Pillar 4: Micro-segmentation — the workload side (apply via kubectl) ──
# Save as k8s/networkpolicy.yaml and apply AFTER observing traffic.
# Default-deny first; then allow only the proven flows.

# k8s/networkpolicy.yaml
# ---
# apiVersion: networking.k8s.io/v1
# kind: NetworkPolicy
# metadata:
#   name: default-deny-all
#   namespace: payments
# spec:
#   podSelector: {}
#   policyTypes: [Ingress, Egress]
# ---
# apiVersion: networking.k8s.io/v1
# kind: NetworkPolicy
# metadata:
#   name: payments-allow-api
#   namespace: payments
# spec:
#   podSelector:
#     matchLabels: { app: payments-api }
#   policyTypes: [Ingress, Egress]
#   ingress:
#     - from:
#         - namespaceSelector: { matchLabels: { name: frontend } }
#           podSelector: { matchLabels: { app: web } }
#       ports: [{ port: 8443 }]
#   egress:
#     - to:
#         - namespaceSelector: { matchLabels: { name: database } }
#       ports: [{ port: 5432 }]
#     - to:                        # DNS must stay open or nothing resolves
#         - namespaceSelector: {}
#           podSelector: { matchLabels: { k8s-app: kube-dns } }
#       ports: [{ port: 53, protocol: UDP }]
