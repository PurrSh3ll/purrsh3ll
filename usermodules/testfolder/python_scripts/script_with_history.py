"""
Simulated Network Scanner (Snmap)
=================================
A CLI tool designed to mimic basic nmap-like scanning functionality.
"""

import argparse
import time


def run_scanner():
    """
    Parses command-line arguments and executes a simulated network scan.
    """
    parser = argparse.ArgumentParser(
        description="Snmap: A simulated network scanning tool."
    )

    # Adding 5 different switches
    parser.add_argument("-t", "--target", required=True, help="Target IP address.")
    parser.add_argument("-p", "--ports", default="80,443", help="Comma-separated ports.")
    parser.add_argument("-sS", "--syn", action="store_true", help="Perform TCP SYN scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-o", "--output", help="Save results to a specific file.")

    args = parser.parse_args()

    print(f"[*] Starting Snmap simulation on {args.target}")

    if args.syn:
        print("[+] Technique: TCP SYN Scan (Stealth Mode)")

    print(f"[*] Scanning ports: {args.ports}")

    if args.verbose:
        print("[+] Verbose mode: Analyzing handshake sequence...")
        time.sleep(1)
        print("[+] Verbose mode: Bypassing basic firewall rules...")

    # Simulation logic
    ports = args.ports.split(',')
    for port in ports:
        print(f"[+] Checking port {port}: OPEN")
        time.sleep(0.5)

    if args.output:
        print(f"[*] Results successfully exported to {args.output}")

    print("[+] Scan completed successfully.")


if __name__ == "__main__":
    run_scanner()