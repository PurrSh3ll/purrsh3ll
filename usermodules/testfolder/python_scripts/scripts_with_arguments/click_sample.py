"""
Security Tool (Legacy version using optparse)
=============================================
Note: optparse is deprecated since Python 3.2.
Use argparse or click for new projects.
"""

from optparse import OptionParser

def main():
    parser = OptionParser(usage="usage: %prog [options] <target>")

    # Adding options
    parser.add_option("-p", "--port", dest="port",
                      help="Target port number", metavar="PORT",
                      type="int", default=80)
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False,
                      help="Enable verbose output")

    (options, args) = parser.parse_args()

    # Handling positional arguments (target)
    if len(args) != 1:
        parser.error("You must specify exactly one target.")

    target = args[0]

    print(f"[*] Starting scan for: {target}")
    print(f"[*] Port: {options.port}")

    if options.verbose:
        print("[+] Verbose mode active: Enumerating services...")

    print("[+] Scan complete.")

if __name__ == "__main__":
    main()