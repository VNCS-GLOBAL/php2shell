#!/bin/bash
# php2shell-simple-check.sh
# Simple local PHP version checker for CVE-2026-109618 / CVE-2026-109619

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== PHP2Shell Simple Version Check ==="
echo "Time: $(date)"
echo

if ! command -v php >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] php command not found${NC}"
    exit 1
fi

PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION.".".PHP_RELEASE_VERSION;' 2>/dev/null)
SAPI=$(php -r 'echo PHP_SAPI;' 2>/dev/null || echo "unknown")

echo "Detected : PHP $PHP_VER"
echo "SAPI     : $SAPI"
echo

if [[ "$PHP_VER" =~ ^8\.2\.([0-9]+)$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 35 ]]; then
        echo -e "${GREEN}[OK] PHP $PHP_VER is patched${NC}"
    else
        echo -e "${RED}[VULNERABLE] PHP $PHP_VER needs >= 8.2.35${NC}"
    fi

elif [[ "$PHP_VER" =~ ^8\.3\.([0-9]+)$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 36 ]]; then
        echo -e "${GREEN}[OK] PHP $PHP_VER is patched${NC}"
    else
        echo -e "${RED}[VULNERABLE] PHP $PHP_VER needs >= 8.3.36${NC}"
    fi

elif [[ "$PHP_VER" =~ ^8\.4\.([0-9]+)$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 27 ]]; then
        echo -e "${GREEN}[OK] PHP $PHP_VER is patched${NC}"
    else
        echo -e "${RED}[VULNERABLE] PHP $PHP_VER needs >= 8.4.27${NC}"
    fi

elif [[ "$PHP_VER" =~ ^8\.5\.([0-9]+)$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 12 ]]; then
        echo -e "${GREEN}[OK] PHP $PHP_VER is patched${NC}"
    else
        echo -e "${RED}[VULNERABLE] PHP $PHP_VER needs >= 8.5.12${NC}"
    fi

elif [[ "$PHP_VER" =~ ^8\.1\. ]] || [[ "$PHP_VER" =~ ^7\. ]] || [[ "$PHP_VER" =~ ^5\. ]]; then
    echo -e "${RED}[VULNERABLE] PHP $PHP_VER is end-of-life / no upstream fix${NC}"

else
    echo -e "${YELLOW}[?] Could not reliably determine status for PHP $PHP_VER${NC}"
    echo "    Please verify manually against official fixed versions."
fi

echo
echo "Note: Always restart PHP / web server after upgrading so the new binary is actually used."