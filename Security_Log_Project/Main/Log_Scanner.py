from pathlib import Path
from datetime import datetime
import re
import csv

ORIGIN = Path(__file__).resolve().parent.parent
logs = ORIGIN / "Logs"
summaries = ORIGIN / "Summaries"

def save_csv(file_n, data):
    with open(summaries/file_n, "a", newline="", encoding="utf-8") as f:
       writer = csv.writer(f)
       for i in data:
           writer.writerow(i)
       writer.writerow([])

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
    data = [("Authentication Summay:", datetime.today().strftime("%Y-%m-%d %H:%M:%S")),
            ("Successful auth:", success),
            ("Failed auth:", failed),
            ("Failed auth connections:", failed_counts),
            ("Most failed auth by:", max(failed_counts, key = failed_counts.get), max(failed_counts.values())),
            ("Accounts locked:", locked_acc),
            ("Last logout:", logout_last),
            ("Unknown status:", unknown),]
    for i in data:
        print(i)
    while True:
        choice_fire = input("Do you want to save this summary? (Y/n): ")
        if choice_fire == "Y":
            print("Saving summary to csv file...")
            save_csv("authentication_summary.csv", data)
            print("Summary saved!")
            break
        elif choice_fire == "n":
            print("Summary not saved...")
            break
        else:
            choice_fire = ""
            print("Please choose either 'Y' to save or 'n' to not save")

def fire_sum():
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
    data = [("Firewall Summay:", datetime.today().strftime("%Y-%m-%d %H:%M:%S")),
            ("Total allowed", allowed),
            ("Total blocked", blocked),
            ("Blocked IP connections",  block_counts),
            ("Repeat blocked", repeat_blocked),
            ("Top blocked", max(block_counts, key = block_counts.get), max(block_counts.values())),
            ("Leaked IPs", leaks)]
    for i in data:
        print(i)
    while True:
        choice_fire = input("Do you want to save this summary? (Y/n): ")
        if choice_fire == "Y":
            print("Saving summary to csv file...")
            save_csv("firewall_summary.csv", data)
            print("Summary saved!")
            break
        elif choice_fire == "n":
            print("Summary not saved...")
            break
        else:
            choice_fire = ""
            print("Please choose either 'Y' to save or 'n' to not save")

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
            print("Please enter a vali number (1, 2, or 3).")
        if choice == 1:
            auth_sum()
        elif choice == 2:
            fire_sum()
        elif choice == 3:
            print("Goodbye...")
            break

if __name__ == "__main__":
    main()