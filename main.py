# !/usr/bin/env python3
import argparse

from dnsclient import DNSClient


def print_key_values_as_tree(dict_: dict, pref=''):
    for key, value in dict_.items():
        print(str(key) + ":")
        if isinstance(value, list):
            for val in value:
                print(pref + "\t" + str(val))
        elif isinstance(value, dict):
            print_key_values_as_tree(value, pref + '\t')
        else:
            print(pref + '\t' + str(value))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Translate hostname to IPv4 address")
    parser.add_argument("hostname", type=str,
                        help="Domain name you want to translate into address")
    parser.add_argument("-r", "--recursion",
                        action="store_true",
                        help="No recursive queries will be sent.")
    parser.add_argument("-6", "--ipv6",
                        action="store_true",
                        help="Show a IPv6 address instead of IPv4")
    parser.add_argument("-s", "--server-address", type=str,
                        default='8.8.8.8:53',
                        help="Custom DNS server address")
    parser.add_argument("-a", "--show-authoritative", action='store_true',
                        help="Show if answer is authoritative")
    parser.add_argument("-d", "--debug", action='store_true',
                        help="Show hex dump of all packets received or sent")
    parser.add_argument("-t", "--tcp", action='store_true',
                        help="Use TCP protocol instead of UDP")
    parser.add_argument("-m", "--timeout", type=int, default=4,
                        help="Set timeouts for replies in seconds")
    return parser.parse_args()


def parse_address(server_address: str):
    if ":" in server_address:
        split = server_address.split(':', 1)
        return split[0], int(split[1])
    return server_address, 53


def main():
    parsed_args = parse_args()
    protocol = 'tcp' if parsed_args.tcp else 'udp'
    client = DNSClient(parsed_args.debug, transport_protocol=protocol,
                       timeout=parsed_args.timeout)

    hostname = parsed_args.hostname
    dns_server_name, dns_server_port = parse_address(
        parsed_args.server_address)
    use_ipv6 = parsed_args.ipv6
    show_is_auth = parsed_args.show_authoritative
    try:
        if parsed_args.recursion:
            ips = client.hostname_to_ip_non_recursive(hostname,
                                                      dns_server_name,
                                                      dns_server_port,
                                                      use_ipv6)
            if show_is_auth:
                ips = map(
                    lambda ip: ip[0] + " - " + ("Authoritative" if ip[1]
                    else "Non-authoritative"), ips)
            else:
                ips = [ip[0] for ip in ips]
            print_key_values_as_tree({hostname: list(ips)})
        else:
            result = client.hostname_to_ip(hostname,
                                           dns_server_address=dns_server_name,
                                           port=dns_server_port,
                                           ipv6=use_ipv6)
            if len(result) <= 1:
                print("Address not found.")
                return
            if show_is_auth:
                print(
                    ("Authoritative" if result[
                        'is_auth'] else "Non-authoritative") \
                    + ' answer')
            result.pop('is_auth')
            print_key_values_as_tree(result)
    except Exception as e:
        print(str(e))


if __name__ == '__main__':
    main()
