#!/bin/bash
# Launch an isolated Chromium/Chrome profile pre-configured to use the
# Interceptor proxy, similar to Burp's "Open Browser" button.
#
# First run: a window opens to http://mitm.it — click through it to install
# mitmproxy's CA certificate for this browser (mitmproxy's own onboarding
# flow, nothing custom here). Without it, HTTPS sites show cert warnings.
# The profile persists at ~/InterceptorBrowserProfile across runs, so you
# only need to do this once.
#
# Uses a non-hidden directory name deliberately: if Chromium/Chrome here is
# installed via snap, its default confinement excludes dotfiles/dot-dirs
# under $HOME unless specially granted, which silently breaks a hidden
# profile dir.
#
# Usage: ./browse.sh [url]

set -euo pipefail

if [ "$EUID" -eq 0 ]; then
    echo "Don't run this as root — a GUI browser launched as root can't display" >&2
    echo "on your desktop session (no access to your DISPLAY/Wayland socket)." >&2
    echo "Run it as your normal user instead, e.g.: ./browse.sh" >&2
    exit 1
fi

if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
    echo "No DISPLAY or WAYLAND_DISPLAY set in this shell — this needs to run" >&2
    echo "from a terminal inside your graphical desktop session, not a raw" >&2
    echo "SSH/TTY shell with no GUI access." >&2
    exit 1
fi

PROFILE_DIR="${HOME}/InterceptorBrowserProfile"
LOG_FILE="${PROFILE_DIR}.log"
PROXY="127.0.0.1:8080"
START_URL="${1:-http://mitm.it}"

BROWSER_BIN=""
for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
        BROWSER_BIN="$candidate"
        break
    fi
done

if [ -z "$BROWSER_BIN" ]; then
    echo "No Chrome/Chromium binary found on PATH." >&2
    echo "Point any browser's proxy settings at $PROXY manually instead." >&2
    exit 1
fi

mkdir -p "$PROFILE_DIR"

echo "Launching $BROWSER_BIN through $PROXY (isolated profile: $PROFILE_DIR)"
echo "Output logged to $LOG_FILE if something goes wrong."
"$BROWSER_BIN" \
    --user-data-dir="$PROFILE_DIR" \
    --proxy-server="$PROXY" \
    --no-first-run \
    --new-window \
    "$START_URL" \
    >"$LOG_FILE" 2>&1 &
disown

sleep 2
if ! kill -0 "$!" 2>/dev/null; then
    echo "Chromium exited immediately instead of staying open — something's wrong. Log:" >&2
    cat "$LOG_FILE" >&2
    exit 1
fi

echo "If this is the first run, install the CA cert from the mitm.it page that just opened."
