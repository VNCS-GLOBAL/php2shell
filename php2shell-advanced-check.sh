#!/bin/bash
# php2shell-advanced-check.sh
# Advanced local checker for PHP2Shell + post-RCE indicators
# Recommended to run as root: sudo bash php2shell-advanced-check.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CRITICAL=0
WARNINGS=0

section()  { echo -e "\n${CYAN}${BOLD}=== $1 ===${NC}"; }
ok()       { echo -e "${GREEN}[OK]${NC} $1"; }
warn()     { echo -e "${YELLOW}[!]${NC} $1"; WARNINGS=$((WARNINGS+1)); }
crit()     { echo -e "${RED}[CRITICAL]${NC} $1"; CRITICAL=$((CRITICAL+1)); }

echo -e "${BOLD}PHP2Shell Advanced Local Security Checker${NC}"
echo "Time : $(date)"
echo "Host : $(hostname)"
echo

########################################
# 1. PHP Version Status
########################################
section "1. PHP Version & Patch Status"

if ! command -v php >/dev/null 2>&1; then
    warn "php binary not found"
else
    PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION.".".PHP_RELEASE_VERSION;' 2>/dev/null || true)
    SAPI=$(php -r 'echo PHP_SAPI;' 2>/dev/null || echo "unknown")
    echo "Detected PHP : $PHP_VER  (SAPI: $SAPI)"

    if [[ "$PHP_VER" =~ ^8\.2\.([0-9]+)$ ]]; then
        [[ ${BASH_REMATCH[1]} -ge 35 ]] && ok "Patched" || crit "VULNERABLE – need >= 8.2.35"
    elif [[ "$PHP_VER" =~ ^8\.3\.([0-9]+)$ ]]; then
        [[ ${BASH_REMATCH[1]} -ge 36 ]] && ok "Patched" || crit "VULNERABLE – need >= 8.3.36"
    elif [[ "$PHP_VER" =~ ^8\.4\.([0-9]+)$ ]]; then
        [[ ${BASH_REMATCH[1]} -ge 27 ]] && ok "Patched" || crit "VULNERABLE – need >= 8.4.27"
    elif [[ "$PHP_VER" =~ ^8\.5\.([0-9]+)$ ]]; then
        [[ ${BASH_REMATCH[1]} -ge 12 ]] && ok "Patched" || crit "VULNERABLE – need >= 8.5.12"
    elif [[ "$PHP_VER" =~ ^8\.1\. ]] || [[ "$PHP_VER" =~ ^7\. ]] || [[ "$PHP_VER" =~ ^5\. ]]; then
        crit "End-of-life / highly likely vulnerable"
    else
        warn "Could not map version $PHP_VER reliably"
    fi

    if php -r 'echo ini_get("session.upload_progress.enabled") ? "1" : "0";' 2>/dev/null | grep -q 1; then
        warn "session.upload_progress.enabled = On"
    else
        ok "session.upload_progress.enabled is Off (or unavailable)"
    fi
fi

########################################
# 2. Suspicious processes
########################################
section "2. Suspicious processes (web users)"

WEB_USERS="www-data|apache|nginx|httpd|php-fpm|nobody|lighttpd"
SUSPICIOUS="bash|sh |dash|zsh|nc |ncat|netcat|python|python3|perl|ruby|php -r|socat|curl.*bash|wget.*bash|/dev/tcp"

FOUND=0
ps auxww | grep -E "$WEB_USERS" | grep -Eiv "grep|php-fpm: pool|apache2 -k|nginx: worker|httpd" | while read -r line; do
    if echo "$line" | grep -Eqi "$SUSPICIOUS"; then
        crit "Suspicious process → $line"
        FOUND=1
    fi
done
[[ $FOUND -eq 0 ]] && ok "No obvious suspicious web-user processes"

########################################
# 3. Network connections
########################################
section "3. Network connections from web processes"

echo "Established connections (review remote IPs carefully):"
ss -tnp state established 2>/dev/null | grep -E 'php|apache|nginx|www-data|httpd' || true
echo
echo "Listening sockets owned by web-related processes:"
ss -tulnp 2>/dev/null | grep -E 'php|apache|nginx|www-data|httpd' || true

########################################
# 4. Recently modified / suspicious files
########################################
section "4. Recently modified PHP files & temp locations"

WEB_ROOTS="/var/www /usr/share/nginx /home/*/public_html /var/www/html /srv/www /opt/bitnami"

echo "PHP files modified in last 7 days:"
find $WEB_ROOTS -type f -name "*.php" -mtime -7 2>/dev/null | head -30 || true
echo

echo "Suspicious files in /tmp, /var/tmp, /dev/shm:"
find /tmp /var/tmp /dev/shm -type f \( -name "*.php" -o -name "*.sh" -o -name "*shell*" -o -perm -111 \) 2>/dev/null | head -20 || true

########################################
# 5. Basic webshell pattern scan
########################################
section "5. Common webshell patterns"

CANDIDATES=$(find $WEB_ROOTS -type f -name "*.php" 2>/dev/null | \
    xargs grep -l -E 'eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|preg_replace\s*\(.*/e|base64_decode\s*\(.*\$_(GET|POST|REQUEST|COOKIE)' 2>/dev/null | head -20)

if [[ -n "$CANDIDATES" ]]; then
    echo "$CANDIDATES" | while read -r f; do
        crit "Possible webshell candidate → $f"
    done
else
    ok "No common webshell patterns found (basic check only)"
fi

########################################
# 6. Persistence
########################################
section "6. Persistence checks"

echo "Crontabs:"
for u in root www-data apache nginx; do
    CRON=$(crontab -u "$u" -l 2>/dev/null | grep -vE '^#|^$' || true)
    if [[ -n "$CRON" ]]; then
        echo "--- $u ---"
        echo "$CRON"
        warn "Review crontab for $u"
    fi
done
echo

echo "SSH authorized_keys under web-related homes:"
find /var/www /usr/share/nginx /home -name authorized_keys 2>/dev/null | while read -r f; do
    crit "Found → $f"
    cat "$f"
done

########################################
# Summary
########################################
section "Summary"

echo "Critical findings : $CRITICAL"
echo "Warnings          : $WARNINGS"
echo

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}${BOLD}→ Investigate critical items immediately.${NC}"
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}→ Some warnings present – please review.${NC}"
else
    echo -e "${GREEN}→ No critical issues detected by this checker.${NC}"
fi

echo
echo "Notes:"
echo " • This is a defensive indicator tool, not full forensics."
echo " • Version check is the most reliable way to know if the host is still vulnerable."
echo " • If you suspect real compromise: isolate, preserve evidence, rotate credentials, rebuild."