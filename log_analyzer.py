import os
import re
import argparse
from datetime import datetime

def extract_data(file_path):

    pattern = r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd-session\[(\d+)\]:\s+Failed password for (\S+) from (\S+) port (\d+)'
    
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return {}
    
    if not os.access(file_path, os.R_OK):
        print(f"Error: Permission denied reading {file_path}")
        print("Try running with: sudo python3 log_analyzer.py")
        return {}
    
    try:
        with open(file_path, 'r') as file:
            results = {}
            print("-" * 60)
            print("Scanning file for failed login attempts...")
            print("-" * 60)
            
            for line in file:
                if "Failed password" in line:
                    match = re.search(pattern, line)
                    if match:
                        timestamp = match.group(1)
                        user = match.group(4)
                        ip = match.group(5)
                        
                        if user in results:
                            results[user].append((timestamp, ip))
                        else:
                            results[user] = [(timestamp, ip)]
        
        return results
        
    except Exception as e:
        print(f"Error reading file: {e}")
        return {}

def brute_force(results, threshold=5, window_seconds=60):

    if not results:
        return
    
    current_year = datetime.now().year
    date_format = "%Y %b %d %H:%M:%S"
    alerts = []
    
    for user, attempts in results.items():
        by_ip = {}
        
        for timestamp_string, ip in attempts:
            full_timestamp = f"{current_year} {timestamp_string}"
            dt = datetime.strptime(full_timestamp, date_format)
            
            if ip not in by_ip:
                by_ip[ip] = []
            by_ip[ip].append(dt)
        
        # Check each IP for brute force pattern
        for ip, times in by_ip.items():
            times.sort()
            
            if len(times) < threshold:
                continue
            
            # Sliding window detection
            for i in range(len(times) - (threshold - 1)):
                time_window = times[i:i+threshold]
                first = time_window[0]
                last = time_window[-1]
                time_diff = (last - first).total_seconds()
                
                if time_diff <= window_seconds:
                    alerts.append({
                        'user': user,
                        'ip': ip,
                        'attempts': len(time_window),
                        'timespan': time_diff,
                        'first': first,
                        'last': last
                    })
                    break
    
    if alerts:
        print("\n" + "=" * 60)
        print("BRUTE FORCE ATTACKS DETECTED")
        print("=" * 60)
        for alert in alerts:
            print(f"\nUser: {alert['user']}")
            print(f"Source IP: {alert['ip']}")
            print(f"Attempts: {alert['attempts']} in {alert['timespan']:.1f} seconds")
            print(f"First attempt: {alert['first']}")
            print(f"Last attempt: {alert['last']}")
        print()
    else:
        print("\nNo brute force attacks detected\n")

def display_results(results):
    if not results:
        print("No failed password attempts found in file\n")
        return
    
    total_users = len(results)
    total_attempts = sum(len(attempts) for attempts in results.values())
    
    print(f"\nTotal users with failed logins: {total_users}")
    print(f"Total failed attempts: {total_attempts}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Analyze authentication logs for brute force attacks'
    )
    parser.add_argument('-f', '--file', 
                       default='/var/log/secure',
                       help='Log file to analyze (default: /var/log/secure)')
    parser.add_argument('-t', '--threshold', 
                       type=int, 
                       default=5,
                       help='Number of failures to trigger alert (default: 5)')
    parser.add_argument('-w', '--window', 
                       type=int, 
                       default=60,
                       help='Time window in seconds (default: 60)')
    
    args = parser.parse_args()
    
    results = extract_data(args.file)
    display_results(results)
    brute_force(results, args.threshold, args.window)

if __name__ == "__main__":
    main()
