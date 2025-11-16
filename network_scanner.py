#!/usr/bin/env python3
"""
Secure, beginner-friendly local network scanner (host discovery by ping).
- Requires explicit consent (--confirm-legal) to run (safety/legal).
- Cross-platform ping (Windows vs POSIX).
- Input validation, concurrency limit, graceful shutdown, secure save option.
"""

import argparse
import ipaddress
import platform
import subprocess
import concurrent.futures
import signal
import sys
import os
import tempfile
from datetime import datetime
from typing import List

# Configuration defaults
DEFAULT_MAX_WORKERS = 30
PING_TIMEOUT_SEC = 1  # per-ping timeout (handled by ping args)
SAVE_FILE_MODE = 0o600  # owner read/write only

# Global for graceful shutdown
shutdown_requested = False


def handle_signal(signum, frame):
    global shutdown_requested
    shutdown_requested = True
    print("\n[+] Shutdown requested. Waiting for running tasks to finish...")


# Register signal handlers
signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


def platform_ping_command(ip: str) -> List[str]:
    """Return a safe ping command list depending on platform."""
    system = platform.system().lower()
    if system == "windows":
        # -n 1 => one echo request; -w 1000 => timeout in ms
        return ["ping", "-n", "1", "-w", "1000", ip]
    else:
        # linux, mac, etc. -c 1 => one packet; -W 1 => timeout in seconds (Linux)
        # macOS uses -W in different ways; we keep -c and timeout via subprocess.timeout
        return ["ping", "-c", "1", "-W", "1", ip]


def ping_host(ip: str) -> bool:
    """Ping a single IP address safely using subprocess (no shell)."""
    try:
        cmd = platform_ping_command(ip)
        # Use subprocess.run with timeout for extra safety; do not capture huge output
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PING_TIMEOUT_SEC + 1)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        # Don't print low-level errors that may confuse users; return False and log if needed.
        return False


def scan_network(network_cidr: str, max_workers: int = DEFAULT_MAX_WORKERS):
    """Scan the provided network CIDR and return list of active hosts."""
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        raise ValueError("Invalid network format. Use e.g. 192.168.1.0/24")

    active = []
    # We use ThreadPoolExecutor for I/O-bound ping calls; limit workers to avoid DoS
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, str(ip)): str(ip) for ip in net.hosts()}
        for future in concurrent.futures.as_completed(future_to_ip):
            if shutdown_requested:
                break
            ip = future_to_ip[future]
            try:
                if future.result():
                    print(f"✔️ Active: {ip}")
                    active.append(ip)
            except Exception:
                # ignore individual host errors, continue scanning
                continue
    return active


def save_results_securely(hosts: List[str], filename: str = None) -> str:
    """Save scan results to a file created with owner-only permissions."""
    if not filename:
        # create a timestamped file in system temp dir
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = os.path.join(tempfile.gettempdir(), f"scan_{ts}.txt")

    # Create file securely: open with os.open and set mode, then write bytes
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(filename, flags, SAVE_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("Scan results - host discovery\n")
            f.write(f"Timestamp (UTC): {datetime.utcnow().isoformat()}Z\n")
            f.write("\n".join(hosts) + ("\n" if hosts else ""))
    except Exception as e:
        # if write fails, ensure file removed to avoid partial files
        try:
            os.remove(filename)
        except Exception:
            pass
        raise e
    return filename


def main():
    parser = argparse.ArgumentParser(description="Safe local network host scanner (ping-based).")
    parser.add_argument("network", help="Network CIDR to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--confirm-legal", action="store_true", help="I confirm I have permission to scan this network")
    parser.add_argument("--save", action="store_true", help="Save results to a secure file (owner-only)")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help=f"Max parallel pings (default {DEFAULT_MAX_WORKERS})")
    args = parser.parse_args()

    # Safety check: explicit confirmation required
    if not args.confirm_legal:
        print("❗ You MUST confirm you have permission to scan the network.")
        print("Re-run with --confirm-legal after obtaining permission.")
        sys.exit(2)

    # Validate max_workers bounds
    if args.max_workers < 1 or args.max_workers > 200:
        print("max-workers must be between 1 and 200")
        sys.exit(2)

    try:
        print(f"[+] Scanning {args.network} (max workers={args.max_workers})")
        hosts = scan_network(args.network, max_workers=args.max_workers)
        print("\n--- Scan Completed ---")
        print(f"Total active hosts: {len(hosts)}")
        if args.save:
            path = save_results_securely(hosts)
            print(f"[+] Results saved to: {path} (owner-only permissions)")
    except ValueError as ve:
        print(f"❌ {ve}")
        sys.exit(2)
    except Exception as e:
        print("❌ An unexpected error occurred. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()
