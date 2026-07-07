"""Intentionally vulnerable CLI sample (for VeriAudit demo ONLY).

Command injection reachable from argv — VeriAudit can reproduce this dynamically
in the sandbox (payload `; echo MARKER`).
"""
import os
import sys


def ping(host):
    # VULN: CWE-78 OS command injection — user input concatenated into shell
    os.system("ping -c 1 " + host)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ping(target)
