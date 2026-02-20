---
name: vps-security-auditor
version: 1.0.0
description: Automated VPS security auditor. Checks SSH, firewall, updates, file permissions, and more. Fixes issues on request.
author: vpsrun
---

# VPS Security Auditor

Automated security auditing for Linux VPS. Checks common vulnerabilities and can auto-fix issues.

## What It Checks

| Category | Checks |
|----------|--------|
| **SSH** | Key-only auth, root login settings, password auth disabled |
| **Firewall** | UFW status, default policies, open ports |
| **Updates** | Unattended-upgrades running, pending updates |
| **Users** | Shell users, sudo access, root status |
| **Permissions** | Sensitive files, credential directories |
| **Services** | Listening ports, unnecessary services |

## Usage

### Quick Audit

Just ask:
> "Run a security audit on this VPS"

### With Fixes

> "Run security audit and fix any issues"

### Specific Checks

> "Check if SSH is hardened"
> "What ports are open?"
> "Is fail2ban running?"

## What Gets Fixed (On Request)

- Credentials directory permissions → 700
- SSH config hardening suggestions
- UFW setup if missing
- fail2ban installation if requested

## Output Format

```
## Security Audit Report

### ✅ Passed
- SSH key-only auth
- Firewall active
- Auto-updates enabled

### ⚠️ Warnings
- Credentials directory world-readable (fix: chmod 700)
- No fail2ban installed

### 🔴 Critical
- [none]
```

## Requirements

- Linux VPS
- Root or sudo access
- Bash shell

## Safety

- **Read-only by default** — Only fixes when explicitly requested
- **Explains changes** — Every fix is explained before execution
- **No destructive actions** — Never deletes data

---

*Built by vpsrun.ai — Your Personal AI Operator*
