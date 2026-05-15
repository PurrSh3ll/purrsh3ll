"""
Simple Argument Parser using sys.argv
=====================================
A basic script demonstrating manual argument handling in Python.
"""

import sys

def print_help():
    """Prints the help manual for the script."""
    print("Usage: python scanner_basic.py <target> <port>")
    print("\nArguments:")
    print("  <target>    The IP address or hostname to scan.")
    print("  <port>      The port number to scan.")

def main():
    """Main execution logic."""
    # sys.argv[0] is the script name itself
    if len(sys.argv) != 3:
        print("[-] Error: Incorrect number of arguments.")
        print_help()
        sys.exit(1)

    target = sys.argv[1]

    try:
        port = int(sys.argv[2])
    except ValueError:
        print("[-] Error: Port must be an integer.")
        sys.exit(1)

    # Simple logic demonstration
    print(f"[*] Starting scan...")
    print(f"[*] Target: {target}")
    print(f"[*] Port: {port}")
    print("[+] Scan completed.")

if __name__ == "__main__":
    main()