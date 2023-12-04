import logging

logger = logging.getLogger("scapy")
logger.setLevel(logging.CRITICAL)

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sr1


def scan_tcp(ip, port, timeout):
    try:
        tcp_syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")

        response = sr1(tcp_syn_packet, timeout=timeout, verbose=False)

        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            if response.haslayer(HTTP):
                service = "HTTP"
            elif response.haslayer(DNS):
                service = "DNS"
            elif "ECHO" in str(response.payload):
                service = "ECHO"
            else:
                service = "-"
            return True, response.time - tcp_syn_packet.time, service
        return False, "-", "-"
    except Exception:
        return False, "-", "-"


def scan_udp(ip, port, timeout):
    try:
        udp_packet = IP(dst=ip) / UDP(dport=port)

        response = sr1(udp_packet, timeout=timeout, verbose=False)

        if response and response.haslayer(UDP):
            if response.haslayer(HTTP):
                service = "HTTP"
            elif response.haslayer(DNS):
                service = "DNS"
            elif "ECHO" in str(response.payload):
                service = "ECHO"
            else:
                service = "-"
            return True, response.time - udp_packet.time, service
        return False, "-", "-"
    except Exception:
        return False, "-", "-"


def worker(protocol, ip, port, timeout, verbose, guess):
    if protocol == 'tcp':
        is_open, timing, service = scan_tcp(ip, port, timeout)
    elif protocol == 'udp':
        is_open, timing, service = scan_udp(ip, port, timeout)
    else:
        raise ValueError(f"Unknown protocol {protocol}")

    if is_open:
        res = Port(port, protocol)
        if verbose:
            res.timing = timing
        if guess:
            res.service = service
        return res


def parse_ports(input_ports):
    ports = defaultdict(set)
    for ports_range in input_ports:
        protocol, port_range = ports_range.split('/')
        for p in port_range.split(','):
            if '-' in p:
                start_port, end_port = map(int, p.split('-'))
                for port in range(start_port, end_port + 1):
                    ports[protocol].add(int(port))
            else:
                ports[protocol].add(int(p))
    return ports


def scan_ports(ip, input_ports, timeout, num_threads, verbose, guess):
    open_ports = []
    threads = []

    ports = parse_ports(input_ports)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, protocol, ip, port, timeout,
                                   verbose, guess)
                   for protocol in ports
                   for port in ports[protocol]]

        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)

    for thread in threads:
        thread.join()

    open_ports.sort(key=lambda port: port.port)

    for port in open_ports:
        print(port)


class Port:
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol.upper()
        self.service = None
        self.timing = None

    def __str__(self):
        res = f"{self.protocol} {self.port}"
        if self.timing:
            res += f" {self.timing :.4f}, ms"
        if self.service:
            res += f" {self.service}"
        return res

    def __repr__(self):
        return self.__str__()
