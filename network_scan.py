import os
import csv
from ipwhois import IPWhois

def resolve_hostname(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        hostname = results['nets'][0]['name']
        return hostname
    except Exception as e:
        print(f"Error resolving {ip}: {e}")
        return None

# Define the range of subnets to scan (10.0.x.0/16)
subnets_to_scan = [f'10.0.{i}.0/16' for i in range(256)]

all_active_hosts = []

for subnet in subnets_to_scan:
    print(f"Scanning {subnet}...")
    
    # Masscan command with rate limiting
    masscan_command = f"masscan {subnet} -p1-65535 --rate=1000"
    
    # Run Masscan and capture the output
    os.system(masscan_command + " > masscan_output.txt")
    
    # Read Masscan output file to extract active IPs
    with open("masscan_output.txt", 'r') as file:
        for line in file:
            if "report for" in line:  # Adjust based on the actual format of your output
                ip_address = line.split()[3]
                all_active_hosts.append(ip_address)

# Resolve hostnames and prepare CSV data
csv_data = []
for ip in all_active_hosts:
    resolved_hostname = resolve_hostname(ip)
    csv_data.append((ip, resolved_hostname or "Unknown"))

# Write to CSV
with open('active_hosts.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['IP Address', 'Hostname'])
    writer.writerows(csv_data)

print("Scan complete. Results saved to active_hosts.csv.")
