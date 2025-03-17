## Nmap Commands
## Nmap (Network Mapper) is a powerful open-source tool used for network discovery, vulnerability scanning, and security auditing. 
## Nmap commands categorized by function covering basic, advanced, security, enumeration, and penetration testing use cases.

## 1. Basic Scanning Commands
•   Default Scan (Basic Ping & Port Scan):

nmap [target]       
Performs a basic scan on the top 1000 TCP ports e.g nmap scanme.nmap.org

•   Scan Multiple Targets:
nmap [target1] [target2] [target3] 

Example: nmap 192.168.1.1 192.168.1.2

To scan an entire subnet:  nmap 192.168.1.0/24

To scan a list of hosts from a file:  nmap -iL targets.txt


## 2. Port Scanning Techniques:
•   TCP SYN Scan (Stealth Scan)

nmap -sS [target]   
Performs a stealthy scan that does not complete the TCP handshake and useful for evading detection by firewalls.

•   TCP Connect Scan:

nmap -sT [target]   
Completes the full TCP handshake (slower and noisier).

•   UDP Scan:

nmap -sU [target]   
Scans UDP ports (useful for detecting services like DNS, SNMP, and DHCP).

•   Comprehensive TCP+UDP Scan:

nmap -sS -sU -p- [target]
Scans all TCP and UDP ports for a full network assessment.


## 3. Port Specification & Scan Range
•   Scan Specific Ports:

nmap -p 22,80,443 [target] 
Scans only ports 22 (SSH), 80 (HTTP), and 443 (HTTPS).

•   Scan All 65535 Ports:

nmap -p- [target]  
Scans all possible ports.

•   Scan Top N Most Common Ports:

nmap --top-ports 100 [target]   
Scans the top 100 commonly used ports.

•   Scan Ports in a Specific Range:

nmap -p 1-1000 [target]
Scans ports 1 to 1000.


## 4. Service and OS Detection

nmap -sV [target]   
Identifies running services and their versions.

•   Detect Operating System:

nmap -O [target]  
Detects operating system details.

•   Aggressive Scan (OS + Service + Script):

nmap -A [target]    
Performs a detailed scan, including: OS detection, Service version detection, Script scanning and  Traceroute


## 5. Firewall & IDS/IPS Evasion Techniques
•   Fragment Packets:

nmap -f [target]        
Sends fragmented packets to bypass firewalls.

•   Spoof Source IP:

nmap -S [spoofed_IP] [target]  
Changes the source IP address to avoid detection.

•   Scan with Decoys:

nmap -D RND:10 [target] 
Uses random decoy IPs to obscure the real scan source.

•   Scan Using a Fake MAC Address:

nmap --spoof-mac 00:11:22:33:44:55 [target]
Uses a fake MAC address.


## 6. Vulnerability Scanning (NSE Scripts)
•   Scan for Basic Vulnerability Detection: 

nmap --script=vuln [target]

•   Scan for Specific Vulnerabilities:

nmap -p 445 --script=smb-vuln-ms17-010 [target] EternalBlue (MS17-010) 

nmap -p 443 --script=ssl-heartbleed [target]    Heartbleed (SSL/TLS)  

•   Scan for Open SMB Shares:

nmap --script smb-enum-shares -p 445 [target]   
Checks for publicly accessible file shares.

•   Scan for HTTP Security Issues:

nmap -p 80 --script=http-security-headers [target]  
Checks for misconfigured HTTP security headers.


## 7. Network Discovery & Enumeration
•   Discover Live Hosts:

nmap -sn [network]  
Sends ICMP Echo Requests (Ping) to find active hosts.

•   Traceroute Scan:

nmap --traceroute [target]  
Maps the network path to the target.

•   Identify Devices on a Network:

nmap -sP 192.168.1.0/24 
Lists all active devices in a subnet.


## 8. Output & Report Generation
•   Save Output in Text Format:

nmap -oN output.txt [target]

•   Save Output in XML Format:

nmap -oX output.xml [target]

•   Save Output in Greppable Format:

nmap -oG output.gnmap [target]



## 9. Performance Optimization
•   Speed Up Scan:

nmap -T5 [target]   
Uses Insane mode for the fastest scan.

nmap --scan-delay 500ms [target]    
Introduces a delay between requests.


## 10. IPv6 Scanning
•   Scan an IPv6 Address:

nmap -6 [IPv6_address]      
Example: nmap -6 2001:db8::1



## 11. Exploitation & Advanced Scans
•   Detect Open RDP Servers:

nmap -p 3389 --script=rdp-enum-encryption [target]

•   Bruteforce SSH Login:

nmap -p 22 --script ssh-brute [target]

•   Scan for CVE-2021-34527 (PrintNightmare):

nmap --script smb-vuln-printnightmare -p 445 [target]


## 12. Full Penetration Testing Nmap Scan

nmap -A -T4 -p- --script=vuln [target]  
Performs a full security audit of the target.



## Automated Nmap Scanning Script using Phyton
## Nmap Scan Automation
import os
import subprocess

def run_nmap_scan(command, target, output_file):
    print(f"\nRunning: {command} on {target}\n")
    result = subprocess.run(command.split(), capture_output=True, text=True)
    with open(output_file, "a") as f:
        f.write(f"\n\nCommand: {command}\n{result.stdout}\n")
    print(result.stdout)

def main():
    target = input("Enter the target IP or domain: ")
    output_file = "nmap_scan_results.txt"
    
    print("\nSelect a scan type:")
    print("1. Basic Scan (-sV)")
    print("2. Aggressive Scan (-A)")
    print("3. Full Port Scan (-p-)")
    print("4. OS Detection (-O)")
    print("5. Vulnerability Scan (--script=vuln)")
    print("6. Firewall Evasion Scan (-f)")
    
    choice = input("Enter your choice (1-6): ")
    
    scan_commands = {
        "1": f"nmap -sV {target}",
        "2": f"nmap -A {target}",
        "3": f"nmap -p- {target}",
        "4": f"nmap -O {target}",
        "5": f"nmap --script=vuln {target}",
        "6": f"nmap -f {target}"
    }
    
    if choice in scan_commands:
        run_nmap_scan(scan_commands[choice], target, output_file)
        print(f"\nResults saved in {output_file}")
    else:
        print("Invalid choice! Exiting...")

if __name__ == "__main__":
    main()

## How It Works:
1.  The user enters the target IP/domain.
2.  Selects a scan type from the menu.
3.  The script executes the Nmap command and saves results in nmap_scan_results.txt.


Nmap Commands Used:
nmap -sV <target>       Basic service version detection

nmap -A <target>        Aggressive scan (includes OS detection, version detection, and script scanning)

nmap -p- <target>       Scans all 65,535 ports

nmap -O <target>        OS detection

nmap --script=vuln <target>     Runs vulnerability scan using Nmap scripts

nmap -f <target>            Fragmented packet scan to evade firewalls


## Features of the Script
•   Interactive menu for selecting scan types.

•   Runs different Nmap commands based on user choice.

•   Saves the results in a log file for future reference.

•   Supports basic, aggressive, OS detection, vulnerability scanning, and firewall evasion scans.


## Enhancements Possible:
•   Automate results parsing

•   Integrate with SIEM for alerts

•   Run scans on multiple targets in parallel
