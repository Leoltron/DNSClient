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
    parser.add_argument("-p", "--server-port",
                        type=int, default=53,
                        help="Custom DNS server port")
    parser.add_argument("-s", "--server-address", type=str,
                        default='8.8.8.8',
                        help="Custom DNS server address")
    parser.add_argument("-a", "--show-authoritative", action='store_true',
                        help="Show if answer is authoritative")
    parser.add_argument("-d", "--debug", action='store_true',
                        help="Show hex dump of all packets received or sent")
    return parser.parse_args()


def main():
    parsed_args = parse_args()
    client = DNSClient(parsed_args.debug)

    hostname = parsed_args.hostname
    dns_server_name = parsed_args.server_address
    dns_server_port = parsed_args.server_port
    use_ipv6 = parsed_args.ipv6
    show_is_auth = parsed_args.show_authoritative
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
        if show_is_auth:
            print(
                ("Authoritative" if result['is_auth'] else "Non-authoritative") \
                + ' answer')
        result.pop('is_auth')
        print_key_values_as_tree(result)


if __name__ == '__main__':
    main()
