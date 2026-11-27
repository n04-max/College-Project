from pathlib import Path
from datetime import datetime
import re
import csv

ORIGIN = Path(__file__).resolve().parent.parent
logs = ORIGIN / "Logs"
summaries = ORIGIN / "Summaries"

def auth_sum():
    failed = 0
    failed_counts = {}
    success = 0
    locked = 0
    locked_acc = []
    logout = 0
    logout_last = {}
    unknown = 0
    pattern = r"src=(\d{1,3}(?:\.\d{1,3}){3})"
    blocked_connections = []
    with open(logs/"authentication.log", encoding="utf-8") as file:
        def line_search(x):
            user = re.search(r"user=(\S*)", x)
            src = re.search(pattern, x)
            when = re.search(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", x)
            return (user.group(1) if user else "unknown",
                    src.group(1) if src else "unknown",
                    when.group(1) if when else "unknown")
        for checks in file:
            if "LOGIN_FAILED" in checks:
                failed += 1
                repeat = re.search(pattern, checks)
                if repeat:
                    ip = repeat.group(1)
                    failed_counts[ip] = failed_counts.get(ip, 0) + 1
            elif "LOGIN_SUCCESS" in checks:
                success += 1
            elif "ACCOUNT_LOCKED" in checks:
                locked += 1
                locked_acc.append(line_search(checks))
            elif "LOGOUT" in checks:
                logout += 1
                user, ip, when = line_search(checks)
                logout_last[user] = (ip, when)
            elif "UNKNOWN" in checks:
                unknown += 1
    print(f"""Login successes: {success}
    Login fails: {failed}
        Failed By: {failed_counts}
        Top failed: {max(failed_counts, key = failed_counts.get)} failed Auth {max(failed_counts.values())}""")
    for user, (ip, when) in logout_last.items():
        print(f"Logouts: {user} from {ip} at {when}")
    for user, ip, when in locked_acc:
        print(f"Accounts Locked: {user} from {ip} at {when}")
    print(f"Login error: {unknown}")
    def gen_auth_sum():
        while True:
            choice_fire = input("Do you want to save this summary? (Y/n): ")
            if choice_fire == "Y":
                print("Saving summary to csv file...")
                if (Path("summaries/Authentication_Summary.csv")).exists() == True:
                    opperation = "w"
                else:
                    opperation = "a"
                with open(summaries/"Authentication_Summary.csv", opperation, newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Authentication Summay:", datetime.today().strftime("%Y-%m-%d %H:%M:%S")])
                    writer.writerow(["Successful auth:", success])
                    writer.writerow(["Failed auth:", failed])
                    writer.writerow(["Failed auth connections:", failed_counts])
                    writer.writerow(["Most failed auth by:", max(failed_counts, key = failed_counts.get), max(failed_counts.values())])
                    writer.writerow(["Accounts locked:", locked_acc])
                    writer.writerow(["Unknown status:", unknown])
                print("Summary saved!")
                break
            elif choice_fire == "n":
                print("Summary not saved...")
                break
            else:
                choice_fire = ""
                print("Please choose either 'Y' to save or 'n' to not save")
    gen_auth_sum()

def fire_log():
    allowed = 0
    blocked = 0
    block_counts = {}
    leaks = {}
    pattern = r"src=(\d{1,3}(?:\.\d{1,3}){3})"
    with open(logs/"suspicious_ips.txt", encoding="utf-8") as file:
        suspicious_ips = [line.strip() for line in file if line.strip()]
    with open(logs/"firewall.log", encoding="utf-8") as file:
        for check in file:
            if "ALLOWED" in check:
                allowed += 1
                repeat = re.search(pattern, check)
                if repeat:
                    ip = repeat.group(1)
                    if ip in suspicious_ips:
                        when = " ".join(check.split()[:2])
                        leaks.update({ip : when})
                    else:
                        pass
            elif "BLOCKED" in check:
                blocked += 1
                repeat = re.search(pattern, check)
                if repeat:
                    ip = repeat.group(1)
                    block_counts[ip] = block_counts.get(ip, 0) + 1
    repeat_blocked = {ip: block_counts.get(ip, 0)
    for ip in suspicious_ips
    if ip in block_counts}
    print(f"""Total allowed connection: {allowed}
    Total blocked connections: {blocked}
    Blocked IP connections: {block_counts}
    Repeat blocked: {repeat_blocked}
    Top blocked: {max(block_counts, key = block_counts.get)} was blocked {max(block_counts.values())} times""")
    for ip, when in leaks.items():
        print(f"""Leaked IPs: {ip} accepted at {when}""")
    def gen_fire_sum():
        while True:
            choice_fire = input("Do you want to save this summary? (Y/n): ")
            if choice_fire == "Y":
                print("Saving summary to csv file...")
                if (Path("summaries/Firewall_Summary.csv")).exists() == True:
                    opperation = "w"
                else:
                    opperation = "a"
                with open(summaries/"Firewall_Summary.csv", opperation, newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Firewall Summay:", datetime.today().strftime("%Y-%m-%d %H:%M:%S")])
                    writer.writerow(["Total allowed", allowed])
                    writer.writerow(["Total blocked", blocked])
                    writer.writerow(["Blocked IP connections",  block_counts])
                    writer.writerow(["Repeat blocked", repeat_blocked])
                    writer.writerow(["Top blocked", max(block_counts, key = block_counts.get), max(block_counts.values())])
                    writer.writerow(["Leaked IPs", leaks])
                print("Summary saved!")
                break
            elif choice_fire == "n":
                print("Summary not saved...")
                break
            else:
                choice_fire = ""
                print("Please choose either 'Y' to save or 'n' to not save")
    gen_fire_sum()

def main():
    print("Log Summarizer Started.")
    while True:
        print("""\nSelect What You Want to Summarize (1 or 2, 3 to quit):
        1. Authentication summary
        2. Firewall summary
        3. Quit
        """)
        try:
            choice = int(input("Your selection: "))
        except ValueError as ERROR:
            choice = 0
            print("Please enter a vali number (1, 2, 3 or 4).")
        if choice == 1:
            auth_sum()
        elif choice == 2:
            fire_log()
        elif choice == 3:
            print("Goodbye...")
            break

if __name__ == "__main__":
    main()