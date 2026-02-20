#!/bin/bash
# VPS Security Auditor v1.0.1
# Run security checks on Linux VPS

set -e

ACTION="${1:-audit}"

echo "## Security Audit Report"
echo ""
echo "**Hostname:** $(hostname)"
echo "**Date:** $(date)"
echo "**OS:** $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "**Action:** $ACTION"
echo ""

# Track results
PASSED=()
WARNINGS=()
CRITICAL=()
FIXED=()

# Check 1: SSH Password auth
check_ssh_password() {
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        PASSED+=("SSH password auth disabled")
    elif grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        if [ "$ACTION" = "fix" ]; then
            sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
            FIXED+=("Disabled SSH password auth")
        else
            WARNINGS+=("SSH password auth enabled (fix: disable it)")
        fi
    fi
}

# Check 2: Root login
check_root_login() {
    if grep -q "^PermitRootLogin prohibit-password\|^PermitRootLogin without-password\|^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        PASSED+=("SSH root login restricted")
    elif grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
        if [ "$ACTION" = "fix" ]; then
            sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
            FIXED+=("Restricted SSH root login")
        else
            WARNINGS+=("SSH root login allowed (fix: restrict it)")
        fi
    fi
}

# Check 3: UFW
check_ufw() {
    UFW_CMD="/usr/sbin/ufw"
    if [ -x "$UFW_CMD" ]; then
        UFW_STATUS=$($UFW_CMD status 2>/dev/null | head -1)
        if echo "$UFW_STATUS" | grep -q "Status: active"; then
            PASSED+=("UFW firewall active")
        else
            if [ "$ACTION" = "fix" ]; then
                echo "y" | $UFW_CMD enable
                FIXED+=("Enabled UFW firewall")
            else
                WARNINGS+=("UFW firewall not active (fix: ufw enable)")
            fi
        fi
    else
        if [ "$ACTION" = "fix" ]; then
            apt-get update && apt-get install -y ufw
            FIXED+=("Installed UFW")
        else
            CRITICAL+=("UFW not installed")
        fi
    fi
}

# Check 4: fail2ban
check_fail2ban() {
    if systemctl is-active fail2ban &>/dev/null; then
        PASSED+=("fail2ban running")
    else
        if command -v fail2ban-client &>/dev/null; then
            if [ "$ACTION" = "fix" ]; then
                systemctl start fail2ban
                systemctl enable fail2ban
                FIXED+=("Started fail2ban")
            else
                WARNINGS+=("fail2ban installed but not running")
            fi
        else
            if [ "$ACTION" = "fix" ]; then
                apt-get update && apt-get install -y fail2ban
                systemctl start fail2ban
                systemctl enable fail2ban
                FIXED+=("Installed and started fail2ban")
            else
                WARNINGS+=("fail2ban not installed")
            fi
        fi
    fi
}

# Check 5: Unattended upgrades
check_autoupdates() {
    if systemctl is-active unattended-upgrades &>/dev/null || [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        PASSED+=("Auto-updates enabled")
    else
        if [ "$ACTION" = "fix" ]; then
            apt-get update && apt-get install -y unattended-upgrades
            systemctl enable unattended-upgrades
            systemctl start unattended-upgrades
            FIXED+=("Enabled auto-updates")
        else
            WARNINGS+=("Auto-updates not configured")
        fi
    fi
}

# Check 6: OpenClaw credentials
check_credentials() {
    if [ -d ~/.openclaw/credentials ]; then
        PERMS=$(stat -c %a ~/.openclaw/credentials 2>/dev/null || echo "unknown")
        if [ "$PERMS" = "700" ]; then
            PASSED+=("OpenClaw credentials secured (700)")
        else
            if [ "$ACTION" = "fix" ]; then
                chmod 700 ~/.openclaw/credentials
                FIXED+=("Secured OpenClaw credentials")
            else
                WARNINGS+=("OpenClaw credentials readable (fix: chmod 700)")
            fi
        fi
    fi
}

# Check 7: Open ports
check_ports() {
    OPEN_PORTS=$(ss -tlnp 2>/dev/null | grep LISTEN | wc -l)
    if [ "$OPEN_PORTS" -lt 5 ]; then
        PASSED+=("Minimal open ports ($OPEN_PORTS)")
    else
        WARNINGS+=("$OPEN_PORTS ports open (review: ss -tlnp)")
    fi
}

# Check 8: Shell users
check_shell_users() {
    SHELL_USERS=$(cat /etc/passwd | grep -E ":/bin/bash|:/bin/sh" | grep -v nologin | wc -l)
    if [ "$SHELL_USERS" -le 2 ]; then
        PASSED+=("Minimal shell users ($SHELL_USERS)")
    else
        WARNINGS+=("$SHELL_USERS shell users (review users)")
    fi
}

# Check 9: World-readable sensitive files
check_sensitive_files() {
    FOUND_INSECURE=0
    # Check private SSH keys (should be 600 or 400)
    for file in ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/id_ecdsa; do
        if [ -f "$file" ]; then
            PERMS=$(stat -c %a "$file" 2>/dev/null)
            # Check if group or other has any read/write/execute
            if [[ "$PERMS" =~ [0-7][1-7][1-7] ]] || [[ "$PERMS" =~ [0-7][0-7][1-7] ]]; then
                CRITICAL+=("$file permissions too open ($PERMS, should be 600)")
                FOUND_INSECURE=1
            fi
        fi
    done
    # Check /etc/shadow - should not be world-readable (last digit should be 0)
    if [ -f /etc/shadow ]; then
        PERMS=$(stat -c %a /etc/shadow 2>/dev/null)
        LAST_DIGIT=$((PERMS % 10))
        if [ $LAST_DIGIT -ne 0 ]; then
            CRITICAL+=("/etc/shadow is world-readable ($PERMS)")
            FOUND_INSECURE=1
        fi
    fi
    if [ $FOUND_INSECURE -eq 0 ]; then
        PASSED+=("Sensitive files secured")
    fi
}

# Run all checks
check_ssh_password
check_root_login
check_ufw
check_fail2ban
check_autoupdates
check_credentials
check_ports
check_shell_users
check_sensitive_files

# Output results
echo "### ✅ Passed (${#PASSED[@]})"
for item in "${PASSED[@]}"; do
    echo "- $item"
done
echo ""

echo "### ⚠️ Warnings (${#WARNINGS[@]})"
if [ ${#WARNINGS[@]} -eq 0 ]; then
    echo "- None"
else
    for item in "${WARNINGS[@]}"; do
        echo "- $item"
    done
fi
echo ""

echo "### 🔴 Critical (${#CRITICAL[@]})"
if [ ${#CRITICAL[@]} -eq 0 ]; then
    echo "- None"
else
    for item in "${CRITICAL[@]}"; do
        echo "- $item"
    done
fi

if [ "$ACTION" = "fix" ] && [ ${#FIXED[@]} -gt 0 ]; then
    echo ""
    echo "### 🔧 Fixed (${#FIXED[@]})"
    for item in "${FIXED[@]}"; do
        echo "- $item"
    done
fi
echo ""

# Summary
TOTAL=${#PASSED[@]}
WARN=${#WARNINGS[@]}
CRIT=${#CRITICAL[@]}

echo "**Summary:** $TOTAL passed, $WARN warnings, $CRIT critical"

if [ "$CRIT" -gt 0 ]; then
    echo ""
    echo "🚨 Critical issues found. Recommend immediate attention."
    exit 2
elif [ "$WARN" -gt 0 ]; then
    echo ""
    if [ "$ACTION" != "fix" ]; then
        echo "💡 Run with 'fix' argument to auto-fix warnings: bash audit.sh fix"
    else
        echo "✅ Fixes applied. Run audit again to verify."
    fi
    exit 1
else
    echo ""
    echo "🎉 This VPS is well-hardened!"
    exit 0
fi
