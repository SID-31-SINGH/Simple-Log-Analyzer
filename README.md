import re
import collections
import os
from datetime import datetime, timedelta

def analyze_apache_access_log(log_file_path, ip_threshold=100, time_window_minutes=5):
    """
    Analyzes Apache access logs for potential unusual activity like high request rates
    from single IPs.

    Args:
        log_file_path (str): Path to the Apache access log file.
        ip_threshold (int): Max requests from a single IP within the time window to flag.
        time_window_minutes (int): Time window in minutes for rate limiting check.

    Returns:
        dict: A dictionary containing detected anomalies.
    """
    print(f"\n[+] Analyzing Apache Access Log: {log_file_path}")
    anomalies = {
        "high_request_ips": [],
        "unusual_status_codes": collections.defaultdict(int),
        "top_requested_pages": collections.Counter(),
        "ip_request_timestamps": collections.defaultdict(list)
    }

    log_pattern = re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - '  # IP address
        r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] ' # Timestamp
        r'"(\S+) (\S+) (\S+)" '                       # Request method, path, protocol
        r'(\d{3}) (\d+|-)'                            # Status code, response size
    )

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                match = log_pattern.match(line)
                if match:
                    ip_address, timestamp_str, method, path, protocol, status_code, response_size = match.groups()

                    # Parse timestamp for time-based analysis
                    try:
                        log_time = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                    except ValueError:
                        # Fallback for simpler timezone format or no timezone
                        try:
                            log_time = datetime.strptime(timestamp_str[:-6], '%d/%b/%Y:%H:%M:%S')
                        except ValueError:
                            # Skip line if timestamp format is not recognized
                            # print(f"[-] Warning: Could not parse timestamp in line {line_num}: {line.strip()}")
                            continue

                    # Count status codes
                    anomalies["unusual_status_codes"][status_code] += 1

                    # Count top requested pages
                    anomalies["top_requested_pages"][path] += 1

                    # Track requests per IP within a sliding window for potential DDoS/brute-force
                    anomalies["ip_request_timestamps"][ip_address].append(log_time)
                    
                    # Remove timestamps older than the window
                    window_start_time = log_time - timedelta(minutes=time_window_minutes)
                    anomalies["ip_request_timestamps"][ip_address] = [
                        t for t in anomalies["ip_request_timestamps"][ip_address] if t >= window_start_time
                    ]

                    # Check for high request rate from a single IP
                    if len(anomalies["ip_request_timestamps"][ip_address]) > ip_threshold:
                        if ip_address not in [ip for ip, _ in anomalies["high_request_ips"]]: # Avoid duplicates
                             anomalies["high_request_ips"].append((ip_address, len(anomalies["ip_request_timestamps"][ip_address])))


                # else:
                #     # print(f"[-] Line {line_num} did not match pattern: {line.strip()}") # Uncomment for debugging unmatched lines

    except FileNotFoundError:
        print(f"[-] Error: Log file not found at '{log_file_path}'.")
        return None
    except Exception as e:
        print(f"[-] An error occurred during Apache log analysis: {e}")
        return None

    return anomalies

def analyze_auth_log(log_file_path, failed_login_threshold=5):
    """
    Analyzes Linux authentication logs (e.g., /var/log/auth.log) for suspicious activities
    like repeated failed login attempts.

    Args:
        log_file_path (str): Path to the authentication log file.
        failed_login_threshold (int): Number of failed attempts from an IP/user to flag.

    Returns:
        dict: A dictionary containing detected anomalies.
    """
    print(f"\n[+] Analyzing Authentication Log: {log_file_path}")
    anomalies = {
        "failed_login_attempts": collections.defaultdict(int),  # (user, ip) -> count
        "successful_logins": collections.defaultdict(int),      # user -> count
        "unusual_user_activity": []                            # (user, ip, time)
    }

    # Example patterns for failed and successful logins. These might need adjustment
    # based on the specific distribution's auth.log format.
    failed_login_pattern = re.compile(
        r'.* authentication failure; .* rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user=(.*)'
    )
    successful_login_pattern = re.compile(
        r'.*Accepted password for (.*) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2'
    )

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Check for failed login attempts
                failed_match = failed_login_pattern.search(line)
                if failed_match:
                    ip_address = failed_match.group(1)
                    user = failed_match.group(2)
                    anomalies["failed_login_attempts"][(user, ip_address)] += 1
                    if anomalies["failed_login_attempts"][(user, ip_address)] >= failed_login_threshold:
                        if (user, ip_address, "failed_brute") not in anomalies["unusual_user_activity"]: # Avoid duplicates
                            anomalies["unusual_user_activity"].append((user, ip_address, "failed_brute_force"))
                            print(f"[!!!] ALERT: Possible brute-force attack from {ip_address} on user '{user}' (>= {failed_login_threshold} failed attempts).")


                # Check for successful logins
                success_match = successful_login_pattern.search(line)
                if success_match:
                    user = success_match.group(1)
                    ip_address = success_match.group(2)
                    anomalies["successful_logins"][user] += 1
                    # Additional checks could be added here, e.g., login from new IP for a user

    except FileNotFoundError:
        print(f"[-] Error: Log file not found at '{log_file_path}'.")
        return None
    except Exception as e:
        print(f"[-] An error occurred during auth log analysis: {e}")
        return None

    return anomalies


def display_results(log_type, anomalies):
    """
    Displays the analysis results in a readable format.
    """
    if not anomalies:
        print(f"\nNo anomalies detected or analysis failed for {log_type} logs.")
        return

    print(f"\n--- Analysis Results for {log_type} Logs ---")

    if log_type == "Apache Access":
        if anomalies["high_request_ips"]:
            print("\nPotential High Request Rate / DDoS Attack IPs:")
            for ip, count in anomalies["high_request_ips"]:
                print(f"  - IP: {ip} ({count} requests in time window)")
        else:
            print("\nNo significant high request rate IPs detected.")

        print("\nHTTP Status Code Distribution:")
        for status, count in sorted(anomalies["unusual_status_codes"].items()):
            print(f"  - {status}: {count} occurrences")
        if any(code for code in ['400', '401', '403', '404', '500', '502'] if anomalies["unusual_status_codes"].get(code, 0) > 0):
             print("  Consider investigating high counts of error codes (4xx, 5xx).")


        print("\nTop 10 Most Requested Pages:")
        for path, count in anomalies["top_requested_pages"].most_common(10):
            print(f"  - {path}: {count} requests")

    elif log_type == "Authentication":
        print("\nFailed Login Attempts (User, IP - counts):")
        if anomalies["failed_login_attempts"]:
            for (user, ip), count in sorted(anomalies["failed_login_attempts"].items(), key=lambda item: item[1], reverse=True):
                print(f"  - User: '{user}', IP: {ip}, Attempts: {count}")
        else:
            print("  No failed login attempts recorded.")

        print("\nUnusual User Activity Alerts:")
        if anomalies["unusual_user_activity"]:
            for user, ip, alert_type in anomalies["unusual_user_activity"]:
                print(f"  - ALERT: {alert_type.replace('_', ' ').title()} for user '{user}' from IP {ip}.")
        else:
            print("  No unusual user activity alerts triggered.")

        print("\nSuccessful Logins (User - counts):")
        if anomalies["successful_logins"]:
            for user, count in sorted(anomalies["successful_logins"].items(), key=lambda item: item[1], reverse=True):
                print(f"  - User: '{user}', Count: {count}")
        else:
            print("  No successful logins recorded.")


    print("\n------------------------------")

def main():
    """Main function to run the log analyzer."""
    print("Welcome to the Simple Python Log Analyzer!")
    print("This tool can help you identify suspicious patterns in log files.")

    # Create dummy log files for demonstration if they don't exist
    if not os.path.exists("dummy_apache_access.log"):
        print("\n[!] Creating dummy_apache_access.log for demonstration...")
        dummy_apache_content = """
192.168.1.1 - - [18/Jun/2025:10:00:01 +0530] "GET /index.html HTTP/1.1" 200 1234
192.168.1.2 - - [18/Jun/2025:10:00:02 +0530] "GET /about.html HTTP/1.1" 200 567
192.168.1.3 - - [18/Jun/2025:10:00:03 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.3 - - [18/Jun/2025:10:00:04 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.3 - - [18/Jun/2025:10:00:05 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.4 - - [18/Jun/2025:10:00:06 +0530] "GET /images/logo.png HTTP/1.1" 200 890
192.168.1.5 - - [18/Jun/2025:10:00:07 +0530] "GET /admin HTTP/1.1" 403 150
192.168.1.3 - - [18/Jun/2025:10:00:08 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.3 - - [18/Jun/2025:10:00:09 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.6 - - [18/Jun/2025:10:00:10 +0530] "GET /contact.html HTTP/1.1" 200 300
192.168.1.3 - - [18/Jun/2025:10:00:11 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.3 - - [18/Jun/2025:10:00:12 +0530] "POST /login HTTP/1.1" 401 200
192.168.1.7 - - [18/Jun/2025:10:00:13 +0530] "GET /robots.txt HTTP/1.1" 200 50
111.111.111.111 - - [18/Jun/2025:10:01:00 +0530] "GET /shell.php HTTP/1.1" 404 120
111.111.111.111 - - [18/Jun/2025:10:01:01 +0530] "GET /shell.php HTTP/1.1" 404 120
111.111.111.111 - - [18/Jun/2025:10:01:02 +0530] "GET /shell.php HTTP/1.1" 404 120
111.111.111.111 - - [18/Jun/2025:10:01:03 +0530] "GET /shell.php HTTP/1.1" 404 120
111.111.111.111 - - [18/Jun/2025:10:01:04 +0530] "GET /shell.php HTTP/1.1" 404 120
"""
        with open("dummy_apache_access.log", "w") as f:
            f.write(dummy_apache_content.strip())
        print("Created 'dummy_apache_access.log'.")

    if not os.path.exists("dummy_auth.log"):
        print("[!] Creating dummy_auth.log for demonstration...")
        dummy_auth_content = """
Jun 18 10:05:01 myhost sshd[1234]: Failed password for invalid user test from 192.168.1.10 port 12345 ssh2
Jun 18 10:05:02 myhost sshd[1235]: Failed password for invalid user admin from 192.168.1.11 port 12346 ssh2
Jun 18 10:05:03 myhost sshd[1236]: Failed password for user root from 192.168.1.10 port 12347 ssh2
Jun 18 10:05:04 myhost sshd[1237]: Failed password for user root from 192.168.1.10 port 12348 ssh2
Jun 18 10:05:05 myhost sshd[1238]: Failed password for user root from 192.168.1.10 port 12349 ssh2
Jun 18 10:05:06 myhost sshd[1239]: Accepted password for user_a from 192.168.1.20 port 54321 ssh2
Jun 18 10:05:07 myhost sshd[1240]: Failed password for user root from 192.168.1.10 port 12350 ssh2
Jun 18 10:05:08 myhost sshd[1241]: Failed password for user root from 192.168.1.10 port 12351 ssh2
Jun 18 10:05:09 myhost sshd[1242]: Failed password for user root from 192.168.1.10 port 12352 ssh2
Jun 18 10:05:10 myhost sshd[1243]: Accepted password for user_b from 192.168.1.21 port 54322 ssh2
Jun 18 10:05:11 myhost sshd[1244]: Failed password for user root from 192.168.1.10 port 12353 ssh2
Jun 18 10:05:12 myhost sshd[1245]: Failed password for user root from 192.168.1.10 port 12354 ssh2
"""
        with open("dummy_auth.log", "w") as f:
            f.write(dummy_auth_content.strip())
        print("Created 'dummy_auth.log'.")


    while True:
        print("\nSelect a log type to analyze:")
        print("1. Apache Access Log (e.g., access.log)")
        print("2. Linux Authentication Log (e.g., auth.log)")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == '1':
            log_path = input("Enter the path to the Apache access log file (e.g., dummy_apache_access.log): ").strip()
            # You can adjust these thresholds for real-world scenarios
            ip_thresh = int(input("Enter IP request threshold (e.g., 5-10 for testing): ") or 5)
            time_win = int(input("Enter time window in minutes for IP threshold (e.g., 5): ") or 5)
            apache_anomalies = analyze_apache_access_log(log_path, ip_thresh, time_win)
            display_results("Apache Access", apache_anomalies)
        elif choice == '2':
            log_path = input("Enter the path to the Linux authentication log file (e.g., dummy_auth.log): ").strip()
            failed_thresh = int(input("Enter failed login threshold (e.g., 5 for testing): ") or 5)
            auth_anomalies = analyze_auth_log(log_path, failed_thresh)
            display_results("Authentication", auth_anomalies)
        elif choice == '3':
            print("Exiting Log Analyzer. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
