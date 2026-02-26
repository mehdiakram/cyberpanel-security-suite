#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# CyberPanel Security Suite — Uninstaller
# Compatible with CyberPanel 2.4.4+
# Author: S M Mehdi Akram | Royal Technologies (https://royaltechbd.com)
# ═══════════════════════════════════════════════════════════════════════════

set -e

PLUGIN_DIR="/usr/local/CyberCP/plugins/securitysuite"
CYBERPANEL_URLS="/usr/local/CyberCP/CyberCP/urls.py"
SETTINGS_FILE="/usr/local/CyberCP/CyberCP/settings.py"
SIDEBAR_FILE="/usr/local/CyberCP/baseTemplate/templates/baseTemplate/index.html"
LOG_FILE="/var/log/securitysuite.log"
MARKER="# SecuritySuite Plugin"
SIDEBAR_MARKER_START="<!-- SecuritySuite Menu Start -->"
SIDEBAR_MARKER_END="<!-- SecuritySuite Menu End -->"

echo "╔══════════════════════════════════════════════╗"
echo "║  CyberPanel Security Suite — Uninstaller     ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "✗ Error: This script must be run as root."
    exit 1
fi

# ── Remove sidebar menu ──────────────────────────────────────────────────
echo "→ Removing sidebar menu…"
if [ -f "$SIDEBAR_FILE" ]; then
    if grep -q "$SIDEBAR_MARKER_START" "$SIDEBAR_FILE"; then
        sed -i "/$SIDEBAR_MARKER_START/,/$SIDEBAR_MARKER_END/d" "$SIDEBAR_FILE"
        echo "  ✓ Sidebar menu removed."
    else
        echo "  ⚠ Sidebar menu not found. Skipping."
    fi
fi

# ── Remove URL route ─────────────────────────────────────────────────────
echo "→ Removing URL route…"
if [ -f "$CYBERPANEL_URLS" ]; then
    if grep -q "$MARKER" "$CYBERPANEL_URLS"; then
        sed -i "/$MARKER/d" "$CYBERPANEL_URLS"
        echo "  ✓ URL route removed."
    else
        echo "  ⚠ URL route not found. Skipping."
    fi
fi

# ── Remove from INSTALLED_APPS ───────────────────────────────────────────
echo "→ Removing from INSTALLED_APPS…"
if [ -f "$SETTINGS_FILE" ]; then
    if grep -q "$MARKER" "$SETTINGS_FILE"; then
        sed -i "/$MARKER/d" "$SETTINGS_FILE"
        echo "  ✓ Removed from INSTALLED_APPS."
    else
        echo "  ⚠ Not found in INSTALLED_APPS. Skipping."
    fi
fi

# ── Remove .pth file ─────────────────────────────────────────────────────
echo "→ Removing Python path file…"
for pth in /usr/local/CyberCP/lib/python3.*/site-packages/securitysuite.pth \
           /usr/local/lib/python3.*/dist-packages/securitysuite.pth; do
    if [ -f "$pth" ]; then
        rm -f "$pth"
        echo "  ✓ Removed: $pth"
    fi
done

# ── Remove plugin directory ──────────────────────────────────────────────
echo "→ Removing plugin directory…"
if [ -d "$PLUGIN_DIR" ]; then
    rm -rf "$PLUGIN_DIR"
    echo "  ✓ Removed: $PLUGIN_DIR"
else
    echo "  ⚠ Plugin directory not found. Skipping."
fi

# ── Remove log file ──────────────────────────────────────────────────────
echo "→ Removing log file…"
if [ -f "$LOG_FILE" ]; then
    rm -f "$LOG_FILE"
    echo "  ✓ Removed: $LOG_FILE"
else
    echo "  ⚠ Log file not found. Skipping."
fi

# Note: Fail2ban is NOT removed, as it may be used by other services.
echo ""
echo "  ℹ  Fail2ban was NOT removed (may be needed by other services)."

# ── Restart service ──────────────────────────────────────────────────────
echo "→ Restarting LiteSpeed (lscpd)…"
if systemctl is-active --quiet lscpd; then
    systemctl restart lscpd
    echo "  ✓ lscpd restarted."
else
    echo "  ⚠ lscpd not found. Restart manually."
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  ✓ Uninstallation Complete!                  ║"
echo "║  All Security Suite files removed cleanly.   ║"
echo "║  (Fail2ban was kept intact)                  ║"
echo "╚══════════════════════════════════════════════╝"
