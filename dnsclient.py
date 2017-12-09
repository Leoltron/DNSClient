# !/usr/bin/env python3
import re
import socket

MESSAGE_LAST_GIVEN_ID = 0

TYPE_A = 0x0001
CLASS_IN = 0x0001

RCODE_ERROR_MESSAGES = {
    1: "Format error",
    2: "Server failure",
    3: "Name Error",
    4: "Not Implemented",
    5: "Refused"
}


def form_host_address_internet_question(hostname, type_, class_):
    return encode_hostname(hostname) + \
           type_.to_bytes(2, byteorder='big') + \
           class_.to_bytes(2, byteorder='big')


def resolve_hostname(hostname, dns_server_hostname="8.8.8.8", port=53):
    result = dict()
    global MESSAGE_LAST_GIVEN_ID
    MESSAGE_LAST_GIVEN_ID += 1
    header = form_header(MESSAGE_LAST_GIVEN_ID, 1, 0, 0, 0)
    question = form_host_address_internet_question(hostname, TYPE_A, CLASS_IN)

    message = send_and_read_udp(dns_server_hostname, port, header + question)
    header_info = decode_message_header(message)
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
        if info["class"] == CLASS_IN and info['type'] == TYPE_A:
            result.setdefault(info['hostname'], []).append(
                get_ip_from_bytes(info['data']))
    return result


def get_ip_from_bytes(bytes_):
    if len(bytes_) != 4:
        raise ValueError("Expected length: 4, got " + str(len(bytes_)))
    return '.'.join([str(i) for i in bytes_])


def to_hex(bytes_):
    for b in bytes_:
        print(hex(b)[2:].zfill(2), end=' ')
    print()


# noinspection SpellCheckingInspection
def form_header(id_, qcount, ancount=0, nscount=0, arcount=0):
    header = bytearray(2 * 6)
    is_response = 0
    opcode = 0000
    is_authorative = 0
    trunc = 0
    recursion_desired = 1
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


def decode_message_header(message):
    result = dict()
    result['id'] = int.from_bytes(message[0:8], byteorder='big')
    info = message[2:4]
    result['is_response'] = info[0] >> 7
    result['opcode'] = (info[0] & 0b01111000) >> 3
    result['is_authorative'] = (info[0] & 0b00000100) >> 2
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
    return encoded_hostname + b'\x00'


def decode_hostname(bytes_, start=0):
    result = ''
    redirected = False
    offset_from_start = 0
    while True:
        octet = bytes_[start]
        if octet == 0:
            if not redirected:
                offset_from_start += 1
            break
        value = octet & 0b00111111
        if octet & 0b11000000 == 0b11000000:
            start = (value << 8) | bytes_[start + 1]
            if not redirected:
                offset_from_start += 2
            redirected = True
        elif not octet & 0b11000000:
            if result:
                result += '.'
            result += bytes_[start + 1:start + 1 + value].decode("ascii")
            start += value + 1
            if not redirected:
                offset_from_start += value + 1
        else:
            raise ValueError("Unexpected first two bytes: "
                             + bin((octet & 0b11000000) >> 6)[2:])
    return result, offset_from_start


def send_and_read_udp(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    while True:
        sock.sendto(message, (ip, port))
        try:
            return sock.recv(1024)
        except socket.timeout:
            print("Timeout has reached, trying again")


def print_key_values_as_tree(dict_: dict):
    for key, value in dict_.items():
        print(str(key)+":")
        for val in value:
            print("\t" + str(val))


def main():
    import sys
    print_key_values_as_tree(resolve_hostname(sys.argv[1]))


if __name__ == '__main__':
    main()
