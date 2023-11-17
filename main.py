import subprocess
import socket
import ipaddress
from tqdm import tqdm
import sys


def write_to_file(file, data):
    with open(file, 'a') as f:
        f.write(data + '\n')


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "Unable to determine local IP"


def get_network_cidr(local_ip):
    ip_parts = local_ip.split('.')
    ip_parts[3] = '0/24'  # Assume /24 network mask
    network_cidr = '.'.join(ip_parts)
    return network_cidr


def is_host_active(ip, timeout=1):
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", str(timeout), ip])
        return True
    except subprocess.CalledProcessError:
        return False


def scan_network(network_cidr, port_range, results_file):
    network = ipaddress.ip_network(network_cidr, strict=False)
    active_hosts = []
    print("Checking active hosts in the network...")
    progress_bar = tqdm(total=len(list(network.hosts())), desc="Scanning hosts", unit="host")

    for ip in network.hosts():
        if is_host_active(str(ip)):
            active_hosts.append(str(ip))
            progress_bar.update(1)

    progress_bar.close()
    write_to_file(results_file, "Active hosts:\n" + "\n".join(active_hosts) + "\n\n")

    for ip in active_hosts:
        open_ports = scan(ip, port_range)
        if open_ports:
            scan_results = nmap_scan(ip, open_ports)
            write_to_file(results_file, f"Scan results for {ip}:\n{scan_results}\n")
            vulnerabilities = analyze_nmap_results(scan_results)
            if vulnerabilities:
                write_to_file(results_file, "Potential vulnerabilities:\n" + "\n".join(vulnerabilities) + "\n")


def scan(target, port_range):
    target_ip = ipaddress.ip_address(target)
    ports_to_scan = range(*port_range)
    open_ports = []

    with tqdm(total=len(ports_to_scan), desc=f"Scanning ports on {target}", unit="port") as progress_bar:
        for port in ports_to_scan:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                conn_status = s.connect_ex((str(target_ip), port))
                if conn_status == 0:
                    open_ports.append(port)
            progress_bar.update(1)

    return open_ports


def nmap_scan(ip, ports):
    ports_str = ','.join(map(str, ports))
    print(f"Starting Nmap scan for {ip} on ports: {ports_str}")
    result = subprocess.check_output(["nmap", "-sV", "-p", ports_str, ip], text=True)
    return result


def analyze_nmap_results(result):
    vulnerabilities = []
    lines = result.split('\n')
    for line in lines:
        if "open" in line and ("http" in line or "ftp" in line or "telnet" in line):
            vulnerabilities.append(line.strip())
    return vulnerabilities


if __name__ == "__main__":
    local_ip = get_local_ip()
    network_cidr = get_network_cidr(local_ip)
    port_range = (1, 1025)  # Default port range
    results_file = "results.txt"

    open(results_file, 'w').close()  # Clear the file

    print(f"Scanning network: {network_cidr}")

    scan_network(network_cidr, port_range, results_file)

    print("Scan completed. Check results in Results.txt file.")
