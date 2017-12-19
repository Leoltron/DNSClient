# !/usr/bin/env python3
import re
import socket

TYPE_A = 0x0001
TYPE_NS = 0x002
TYPE_SOA = 0x006
TYPE_AAAA = 0x001c

CLASS_IN = 0x0001

RCODE_ERROR_MESSAGES = {
    1: "Format error",
    2: "Server failure",
    3: "Name Error",
    4: "Not Implemented",
    5: "Refused"
}

DEBUG = False


def debug(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)


def form_host_address_internet_question(hostname, type_, class_):
    return encode_hostname(hostname) + \
           type_.to_bytes(2, byteorder='big') + \
           class_.to_bytes(2, byteorder='big')


def get_ipv4_from_bytes(bytes_):
    if len(bytes_) != 4:
        raise ValueError("Expected length: 4, got " + str(len(bytes_)))
    return '.'.join([str(i) for i in bytes_])


def get_ipv6_from_bytes(bytes_):
    if len(bytes_) != 16:
        raise ValueError("Expected length: 16, got " + str(len(bytes_)))
    return ':'.join(
        [hex((bytes_[i] << 8) + bytes_[i + 1])[2:] for i in range(0, 16, 2)])


def to_hex(bytes_):
    result = ''
    for b in bytes_:
        result += hex(b)[2:].zfill(2).upper() + ' '
    return result


# noinspection SpellCheckingInspection
def form_header(id_, qcount, ancount=0, nscount=0, arcount=0, recursive=True):
    header = bytearray(2 * 6)
    is_response = 0
    opcode = 0000
    is_authorative = 0
    trunc = 0
    recursion_desired = int(recursive)
    recursion_available = 0
    z = 000
    rcode = 0000
    info = bytearray(2)
    # числа слева от & для наглядности.
    info[0] = \
        (0b10000000 & (is_response << 7)) | \
        (0b01111000 & (opcode << 3)) | \
        (0b00000100 & (is_authorative << 2)) | \
        (0b00000010 & (trunc << 1)) | \
        (0b00000001 & recursion_desired)
    info[1] = \
        (0b10000000 & (recursion_available << 7)) | \
        (0b01110000 & (z << 4)) | \
        (0b00001111 & rcode)

    header[0:8] = id_.to_bytes(length=2, byteorder='big')
    header[2:4] = info
    header[4:6] = qcount.to_bytes(length=2, byteorder='big')
    header[6:8] = ancount.to_bytes(length=2, byteorder='big')
    header[8:10] = nscount.to_bytes(length=2, byteorder='big')
    header[10:12] = arcount.to_bytes(length=2, byteorder='big')
    return bytes(header)


def decode_dns_message(message, errors='raise'):
    errors = errors.lower()
    result = dict()
    result['header'] = header = decode_message_header(message)

    response_code = header['rcode']
    if response_code != 0 and errors != 'ignore':
        n = (None,) * 5
        if errors == 'return_none':
            return n

        error_message = "Unspecified error"
        if response_code in RCODE_ERROR_MESSAGES:
            error_message = RCODE_ERROR_MESSAGES[response_code]
        if errors == 'raise':
            raise ValueError(error_message)
        return n

    start = 12

    result['questions'] = questions = []
    for i in range(header['qdcount']):
        question, offset = decode_question(message, start)
        questions.append(question)
        start += offset
    result['answers'] = answers = []
    for i in range(header['ancount']):
        answer, offset = decode_rs(message, start)
        answers.append(answer)
        start += offset
    result['authority_records'] = authority_records = []
    for i in range(header['nscount']):
        ns, offset = decode_rs(message, start)
        authority_records.append(ns)
        start += offset
    result['additional_records'] = additional_records = []
    for i in range(header['arcount']):
        ar, offset = decode_rs(message, start)
        additional_records.append(ar)
        start += offset

    return result


def decode_message_header(message):
    result = dict()
    result['id'] = int.from_bytes(message[0:2], byteorder='big')
    info = message[2:4]
    result['is_response'] = info[0] >> 7
    result['opcode'] = (info[0] & 0b01111000) >> 3
    result['is_authoritative'] = (info[0] & 0b00000100) >> 2
    result['trunc'] = (info[0] & 0b00000010) >> 1
    result['recursion_desired'] = (info[0] & 0b00000001)
    result['recursion_available'] = (info[1] & 0b10000000) >> 7
    result['rcode'] = info[1] & 0b1111
    result['qdcount'] = int.from_bytes(message[4:6], byteorder='big')
    result['ancount'] = int.from_bytes(message[6:8], byteorder='big')
    result['nscount'] = int.from_bytes(message[8:10], byteorder='big')
    result['arcount'] = int.from_bytes(message[10:12], byteorder='big')
    return result


def decode_question(message, start):
    result = dict()
    hostname, offset = decode_hostname(message, start)
    result['hostname'] = decode_hostname(message, start)
    result['type'] = int.from_bytes(
        message[start + offset:start + offset + 2], byteorder='big')
    result['class'] = int.from_bytes(
        message[start + offset + 2:start + offset + 4], byteorder='big')
    return result, offset + 4


def decode_rs(message, start):
    result = dict()
    result['hostname'], hostname_offset = decode_hostname(message, start)
    start += hostname_offset
    result['type'] = int.from_bytes(message[start:start + 2],
                                    byteorder='big')
    start += 2
    result['class'] = int.from_bytes(message[start:start + 2],
                                     byteorder='big')
    start += 2
    result['TTL'] = int.from_bytes(message[start:start + 4],
                                   byteorder='big')
    start += 4
    data_length = int.from_bytes(message[start:start + 2],
                                 byteorder='big')
    start += 2
    result['data_start'] = start
    result['data'] = message[start: start + data_length]
    total_entry_length = hostname_offset + 10 + data_length
    return result, total_entry_length


HOSTNAME_PART_PATTERN = re.compile(r"[a-zA-Z0-9-]{1,63}")


def encode_hostname(hostname: str):
    splitted_hostname = hostname.split('.')
    encoded_hostname = b''
    for part in splitted_hostname:
        if not HOSTNAME_PART_PATTERN.fullmatch(part):
            raise ValueError()
        encoded_hostname += bytes([len(part)]) + part.encode(encoding="ascii")
    debug('Encode hostname: "' + hostname + '" -> ' + to_hex(
        encoded_hostname + b'\x00'))
    return encoded_hostname + b'\x00'


def decode_hostname(bytes_, start=0):
    debug('Decode hostname: ' + to_hex(bytes_[start:]))
    debug("From octet #" + str(start))
    result = ''
    redirected = False
    offset_from_start = 0
    while True:
        octet = bytes_[start]
        debug("\toctet #{:d} {}: ".format(start, bin(octet)[2:].zfill(8)),
              end='')
        if octet == 0:
            debug("end of name.")
            if not redirected:
                offset_from_start += 1
            break
        value = octet & 0b00111111
        if octet & 0b11000000 == 0b11000000:
            start = (value << 8) | bytes_[start + 1]
            debug("redirection to octet " + str(start))
            if not redirected:
                offset_from_start += 2
            redirected = True
        elif not octet & 0b11000000:
            debug("pointer to string with length " + str(value))
            if result:
                result += '.'
            result += bytes_[start + 1:start + 1 + value].decode("ascii")
            start += value + 1
            if not redirected:
                offset_from_start += value + 1
            debug('\tCurrent string: "' + str(result) + '"')
        else:
            debug('unspecified')
            raise ValueError("Unexpected first two bytes: "
                             + bin((octet & 0b11000000) >> 6)[2:].zfill(2))
    debug(' -> "' + result + '"')
    return result, offset_from_start


def send_and_read_udp(ip, port, message, print_content, tries=4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try_ = 0
    while True:
        if print_content:
            print("Sending " + to_hex(message))
        sock.sendto(message, (ip, port))
        try:
            reply = sock.recv(1024)
            if print_content:
                print("Received " + to_hex(reply))
            return reply
        except socket.timeout:
            try_ += 1
            if try_ > tries > 0:
                raise TimeoutError("Out of tries")
            print("Timeout has reached, trying again")


def join_rslices(sep, list_):
    result = ''
    for i in range(len(list_) - 1, -1, -1):
        if result:
            result = sep + result
        result = list_[i] + result
        yield result


class DNSClient:
    def __init__(self, print_message_contents):
        self.print_message_contents = print_message_contents
        self.next_message_id = 1
        self.ipv4_cache = dict()
        self.ipv6_cache = dict()
        self.domain_authorities = dict()
        self.is_ip_from_authoritative = dict()

    def handle_auth_records(self, message_bytes, auth_records, is_auth):
        for auth_record in auth_records:
            if auth_record['type'] == TYPE_NS:
                hostname = auth_record['hostname'].lower()
                if hostname not in self.domain_authorities:
                    self.domain_authorities[hostname] = list()
                self.domain_authorities[hostname] \
                    .append(
                    decode_hostname(message_bytes, auth_record['data_start'])[
                        0].lower())
            else:
                self.handle_record(message_bytes, auth_record, is_auth)

    def handle_record(self, message, record, is_auth):
        if record['type'] == TYPE_A:
            self.handle_ipv4_record(record, is_auth)
        elif record['type'] == TYPE_AAAA:
            self.handle_ipv6_record(record, is_auth)

    def handle_ipv4_record(self, record, is_authoritative):
        hostname = record['hostname'].lower()
        if hostname not in self.ipv4_cache:
            self.ipv4_cache[hostname] = list()
        ipv4 = get_ipv4_from_bytes(record['data'])
        self.ipv4_cache[hostname].append(ipv4)
        self.is_ip_from_authoritative[ipv4] = is_authoritative

    def handle_ipv6_record(self, record, is_authoritative):
        hostname = record['hostname'].lower()
        if hostname not in self.ipv6_cache:
            self.ipv6_cache[hostname] = list()
        ipv6 = get_ipv6_from_bytes(record['data'])
        self.ipv6_cache[hostname].append(ipv6)
        self.is_ip_from_authoritative[ipv6] = is_authoritative

    def hostname_to_ip(self,
                       hostname: str,
                       dns_server_address="8.8.8.8",
                       port=53,
                       ipv6=False):
        hostname = hostname.lower()
        type_ = TYPE_AAAA if ipv6 else TYPE_A
        result = dict()
        header = form_header(self.next_message_id, 1, 0, 0, 0)
        self.next_message_id += 1
        question = form_host_address_internet_question(hostname, type_,
                                                       CLASS_IN)

        message = send_and_read_udp(dns_server_address, port,
                                    header + question,
                                    self.print_message_contents)
        header_info = decode_message_header(message)
        result['is_auth'] = header_info['is_authoritative']
        response_code = header_info['rcode']
        if response_code != 0:
            error_message = "Unspecified error"
            if response_code in RCODE_ERROR_MESSAGES:
                error_message = RCODE_ERROR_MESSAGES[response_code]
            raise ValueError(error_message)
        start = 12
        for _ in range(header_info['qdcount']):
            start += decode_question(message, start)[1]
        for _ in range(header_info['ancount']):
            info, entry_len = decode_rs(message, start)
            start += entry_len
            if info["class"] == CLASS_IN and info['type'] == type_:
                result.setdefault(info['hostname'], []).append(
                    get_ipv6_from_bytes(info['data']) if ipv6 else
                    get_ipv4_from_bytes(info['data']))
        return result

    def ask_for_ip(self, host_to_look, server, port, ipv6, recursive):
        type_ = TYPE_AAAA if ipv6 else TYPE_A
        header = form_header(self.next_message_id, 1, 0, 0, 0,
                             recursive=recursive)
        self.next_message_id += 1
        question = form_host_address_internet_question(host_to_look,
                                                       type_,
                                                       CLASS_IN)

        reply_bytes = send_and_read_udp(server, port, header + question,
                                        self.print_message_contents, )
        reply = decode_dns_message(reply_bytes, errors='return_none')
        if reply == (None,) * 5:
            return False
        is_auth = reply['header']['is_authoritative']
        for answer in reply['answers']:
            self.handle_record(reply, answer, is_auth)
        self.handle_auth_records(reply_bytes, reply['authority_records'],
                                 is_auth)

        for additional_record in reply['additional_records']:
            self.handle_record(reply, additional_record, is_auth)

    def hostname_to_ip_non_recursive(self, hostname,
                                     dns_server_address="8.8.8.8",
                                     port=53,
                                     ipv6=False):
        hostname = hostname.lower()
        cache = self.ipv6_cache if ipv6 else self.ipv4_cache
        last_authorities = list()
        asked_server = False
        while True:
            if hostname in cache:
                ips = cache[hostname]
                return list(zip(ips,
                                [bool(self.is_ip_from_authoritative[ip]) for ip
                                 in ips]))
            else:
                auth = self.get_authorities(hostname)
                if auth is not None:
                    if auth == last_authorities:
                        raise RecursionError
                    else:
                        auth_server = auth[0]
                        auth_server_ip = self.hostname_to_ip_non_recursive(
                            auth_server, dns_server_address, port)[0][0]
                        self.ask_for_ip(hostname, auth_server_ip, port, ipv6,
                                        False)
                elif asked_server:
                    raise RecursionError
                else:
                    asked_server = True
                    self.ask_for_ip(hostname, dns_server_address, port, ipv6,
                                    False)

    def get_authorities(self, name):
        for d in list(join_rslices('.', name.split('.')))[::-1]:
            if d in self.domain_authorities:
                return self.domain_authorities[d]
        return None
