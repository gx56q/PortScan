import argparse

from scanner import scan_ports


def parse_args():
    parser = argparse.ArgumentParser(description="TCP and UDP port scanner")

    parser.add_argument("ip_address", type=str, help="Target IP address")
    parser.add_argument("ports", nargs="+", type=str,
                        help="Ports to scan in the format {tcp|udp}"
                             "[/[PORT|PORT-PORT],...]")

    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="Timeout for response (default: 2 seconds)")
    parser.add_argument("-j", "--num-threads", type=int, default=1,
                        help="Number of threads")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose mode")
    parser.add_argument("-g", "--guess", action="store_true",
                        help="Guess application layer protocol")

    input_args = parser.parse_args()
    return input_args


if __name__ == "__main__":
    args = parse_args()
    scan_ports(args.ip_address, args.ports, args.timeout, args.num_threads,
               args.verbose, args.guess)
