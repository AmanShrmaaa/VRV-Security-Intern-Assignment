import re
import csv
from collections import defaultdict, Counter

# Configurable threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parses the log file and extracts relevant information."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)
    
    # Regular expressions for parsing the log file
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>/\S*) HTTP/\d+\.\d+" (?P<status>\d+)'
    )
    
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = int(match.group('status'))
                
                # Count requests per IP and endpoint
                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1
                
                # Count failed login attempts (status code 401)
                if status == 401:
                    failed_logins[ip] += 1
    
    return ip_requests, endpoint_requests, failed_logins

def analyze_ip_requests(ip_requests):
    """Returns sorted IP request counts."""
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

def analyze_endpoints(endpoint_requests):
    """Returns the most frequently accessed endpoint."""
    most_accessed = endpoint_requests.most_common(1)
    return most_accessed[0] if most_accessed else None

def detect_suspicious_activity(failed_logins):
    """Identifies IPs exceeding the failed login threshold."""
    return [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]

def save_to_csv(ip_requests, most_accessed, suspicious_activities, output_file):
    """Saves the results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP section
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])
        writer.writerow([])  # Blank line for separation
        
        # Write Most Accessed Endpoint section
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if most_accessed:
            writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])  # Blank line for separation
        
        # Write Suspicious Activity section
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities:
            writer.writerow([ip, count])

def main():
    log_file = "sample.log"
    output_file = "log_analysis_results.csv"
    
    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file)
    
    # Analyze data
    sorted_ip_requests = analyze_ip_requests(ip_requests)
    most_accessed_endpoint = analyze_endpoints(endpoint_requests)
    suspicious_activities = detect_suspicious_activity(failed_logins)
    
    # Display results
    print("Requests per IP Address:")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")
    print()
    
    print("Most Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print()
    
    print("Suspicious Activity Detected:")
    for ip, count in suspicious_activities:
        print(f"{ip:<20} {count}")
    print()
    
    # Save results to CSV
    save_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activities, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
