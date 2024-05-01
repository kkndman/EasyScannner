import nmap
import sys
import os

# Check for correct command line arguments
if len(sys.argv) < 3:
    print("Usage: python3 scanner.py <ip_or_range> <port_or_range>")
    print("Example: python3 scanner.py 192.168.1.1 22-80")
    sys.exit(1)

# Get the IP address or range and port or range from command line arguments
ip_or_range = sys.argv[1]
port_or_range = sys.argv[2]

# Create an instance of the nmap.PortScanner class
scanner = nmap.PortScanner()

# Function to handle Ctrl+C interrupt
def signal_handler(sig, frame):
    print("\nScan interrupted. Exiting...")
    sys.exit(0)

# Register the signal handler for Ctrl+C
import signal
signal.signal(signal.SIGINT, signal_handler)

# Scan the specified IP address or range with service version detection
scan_results = scanner.scan(ip_or_range, arguments=f"-p {port_or_range} -sV")

# Create the output directory if it doesn't exist
output_dir = "/home/kali/n-scans"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Iterate over each host in the results
for host in scanner.all_hosts():
    # Get the results for the current host
    host_results = scan_results['scan'][host]
    
    # Open a file for writing the results for the current host
    output_file = os.path.join(output_dir, f"{host}.txt")
    with open(output_file, "w") as f:
        # Write the host information and port scan results to the file
        f.write(f"Host: {host}\n")
        f.write(f"Ports scanned: {port_or_range}\n\n")
        
        # Iterate over each port in the results for the current host
        for port in host_results['tcp']:
            port_info = host_results['tcp'][port]
            f.write(f"Port: {port}\n")
            f.write(f"State: {port_info['state']}\n")
            f.write(f"Service: {port_info['name']}\n")
            
            # Check if the 'product' and 'version' keys exist in the port_info dictionary
            if 'product' in port_info and 'version' in port_info:
                f.write(f"Product: {port_info['product']}\n")
                f.write(f"Version: {port_info['version']}\n")
            else:
                f.write(f"Product: Unknown\n")
                f.write(f"Version: Unknown\n")
            
            f.write("\n")

print("Scan complete. Results saved to separate text files in the /home/kali/n-scans directory for each host.")
