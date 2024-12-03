import csv
from collections import Counter, defaultdict

class LogAnalyzer:
    def __init__(self, log_file):
        with open(log_file, 'r') as f:
            self.logs = f.read()
    
    def count_per_ip(self):
        """Counts the occurrences of each IP address in the logs."""
        ips = [line.split()[0] for line in self.logs.splitlines()]
        return Counter(ips)
    
    def most_accessed_endpoints(self):
        """Finds the most accessed endpoint in the logs."""
        endpoints = [line.split()[6] for line in self.logs.splitlines()]
        counter = Counter(endpoints)
        most_accessed, max_count = counter.most_common(1)[0]
        return {most_accessed: max_count}
    
    def suspicious_activity(self, threshold=10):
        """Detects suspicious activity based on failed login attempts."""
        failed_attempts = defaultdict(int)
        
        for line in self.logs.splitlines():
            parts = line.split()
            
            if len(parts) > 8 and (parts[8] == "401" or "Invalid credentials" in line):
                failed_attempts[parts[0]] += 1
        
        
        flagged_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
        
        
        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20}{'Failed Login Attempts'}")
        for ip, count in flagged_ips.items():
            print(f"{ip:<20}{count}")
        
        return flagged_ips
    
    def save_to_csv(self, ip_counts, most_accessed, suspicious_ips, output_file="log_analysis_results.csv"):
        """Saves the results to a CSV file."""
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            
            writer.writerow(["Analysis Type", "Detail", "Count"])
            
            
            writer.writerow(["IP Access Counts", "IP Address", "Request Count"])
            for ip, count in ip_counts.items():
                writer.writerow(["", ip, count])
            
            
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint", "Endpoint", "Access Count"])
            for endpoint, count in most_accessed.items():
                writer.writerow(["", endpoint, count])
            
            
            writer.writerow([])
            writer.writerow(["Suspicious Activity", "IP Address", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                writer.writerow(["", ip, count])
        
        print(f"\nResults have been saved to {output_file}")


log_analyzer = LogAnalyzer('sample.log')


ip_counts = log_analyzer.count_per_ip()
print("IP Access Counts:", ip_counts)


most_accessed = log_analyzer.most_accessed_endpoints()
print("\nMost Accessed Endpoint:", most_accessed)


suspicious_ips = log_analyzer.suspicious_activity(threshold=4)
print("\nFlagged IPs:", suspicious_ips)


log_analyzer.save_to_csv(ip_counts, most_accessed, suspicious_ips)
