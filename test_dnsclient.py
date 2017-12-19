# !/usr/bin/env python3
import unittest

import dnsclient


class IPResolvingTests(unittest.TestCase):
    def test_resolve_ipv4(self):
        byte_ip = [192, 168, 87, 255]
        self.assertEqual("192.168.87.255",
                         dnsclient.get_ipv4_from_bytes(byte_ip))

    def test_resolve_ipv4_error_little(self):
        byte_ip = [192, 168, 87]
        self.assertRaises(ValueError, dnsclient.get_ipv4_from_bytes, (byte_ip))

    def test_resolve_ipv4_error_big(self):
        byte_ip = [192, 168, 87, 35, 5]
        self.assertRaises(ValueError, dnsclient.get_ipv4_from_bytes, (byte_ip))

    def test_resolve_ipv6(self):
        byte_ip = b"\xa9\x87\x00\x00\xa6\x88\xbb\xaf\xa9\x87\x00\x00\xa6\x88\x0b\xaf"
        self.assertEqual("a987:0:a688:bbaf:a987:0:a688:baf",
                         dnsclient.get_ipv6_from_bytes(byte_ip))

    def test_resolve_ipv6_error_little(self):
        byte_ip = b"\xa9\x87\x00\x00\xa6\x88\xaf\xa9\x87\x00\x00\xa6\x88\x0b\xaf"
        self.assertRaises(ValueError, dnsclient.get_ipv6_from_bytes, (byte_ip))

    def test_resolve_ipv6_error_big(self):
        byte_ip = b"\xa9\x87\x00\x00\xa6\x88\xbb\xaf\xa9\x87\x00\x00\xa6\x88\x0b\xaf\x55"
        self.assertRaises(ValueError, dnsclient.get_ipv6_from_bytes, (byte_ip))


class UtilsTests(unittest.TestCase):
    def test_join_r_slices(self):
        a = ["abcd", "gsd", "tfgbnj", "YD G"]
        expected = ["YD G", "tfgbnj.YD G", "gsd.tfgbnj.YD G",
                    "abcd.gsd.tfgbnj.YD G"]
        self.assertEqual(expected, list(dnsclient.join_rslices('.', a)))


class HostnameDecoderTests(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(b"\x03abc\x06google\x02ru\x00",
                         dnsclient.encode_hostname("abc.google.ru"))

    def test_decode_simple(self):
        self.assertEqual(("abc.google.ru", 15),
                         dnsclient.decode_hostname(
                             b"\x03abc\x06google\x02ru\x00", 0))

    def test_decode_with_offset(self):
        self.assertEqual(("abc.google.ru", 15),
                         dnsclient.decode_hostname(
                             b"\x55\x87\xac\x03abc\x06google\x02ru\x00", 3))

    def test_decode_with_pointer(self):
        self.assertEqual(("abc.google.ru", 6),
                         dnsclient.decode_hostname(
                             b"\x55\x06google\x02ru\x00\x03abc\xc0\x01", 12))

    def test_decode_error(self):
        self.assertRaises(ValueError, dnsclient.decode_hostname, (
            b"\x55\x06google\x02ru\x00\x43abc\xc0\x01"), 12)


class DNSMessageEncoderTests(unittest.TestCase):
    def test_form_header(self):
        expected = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        actual = dnsclient.form_header(1, qcount=1, recursive=True)
        self.assertEqual(expected, actual)

    def test_decode_header(self):
        header = b'\x00\x01\x01\x00\x00\x01\x00\x05\x00\x08\x01\x55'
        result = dnsclient.decode_message_header(header)
        self.assertEqual(1, result['id'])
        self.assertEqual(0, result['is_response'])
        self.assertEqual(0, result['opcode'])
        self.assertEqual(0, result['is_authoritative'])
        self.assertEqual(0, result['trunc'])
        self.assertEqual(1, result['recursion_desired'])
        self.assertEqual(0, result['recursion_available'])
        self.assertEqual(0, result['rcode'])
        self.assertEqual(1, result['qdcount'])
        self.assertEqual(5, result['ancount'])
        self.assertEqual(8, result['nscount'])
        self.assertEqual(341, result['arcount'])

    def test_encode_question(self):
        self.assertEqual(b'\x03boo\x08leoltron\x02ru\x00\x00\x01\x00\x01',
                         dnsclient.
                         form_host_address_internet_question("boo.leoltron.ru",
                                                             dnsclient.TYPE_A,
                                                             dnsclient.CLASS_IN))

    def test_decode_question(self):
        question = b'\x03boo\x08leoltron\x02ru\x00\x00\x01\x00\x01'
        decoded_question, offset = dnsclient.decode_question(question, 0)
        self.assert_decoded_question(decoded_question, offset,
                                     'boo.leoltron.ru', 17)

    def test_decode_question_offset(self):
        question = b'\x00\x00\x00\x03boo\x08leoltron\x02ru\x00\x00\x01\x00\x01'
        decoded_question, offset = dnsclient.decode_question(question, 3)
        self.assert_decoded_question(decoded_question, offset,
                                     'boo.leoltron.ru', 17)

    def assert_decoded_question(self, decoded_question, offset,
                                hostname, hostname_offset):
        self.assertEqual(offset, 21)
        self.assertEqual(decoded_question['hostname'][0], hostname)
        self.assertEqual(decoded_question['hostname'][1], hostname_offset)
        self.assertEqual(decoded_question['type'], dnsclient.TYPE_A)
        self.assertEqual(decoded_question['class'], dnsclient.CLASS_IN)

    def test_decode_rs(self):
        rs = b'\x00\x01\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x06\x70\x69' \
             b'\x6b\x61\x62\x75\x02\x72\x75\x00\x00\x01\x00\x01\xc0\x0c\x00' \
             b'\x01\x00\x01\x00\x00\x01\x92\x00\x04\xd4\xe0\x70\xc1\xc0\x0c' \
             b'\x00\x01\x00\x01\x00\x00\x01\x92\x00\x04\x5b\xe4\x9b\x5e\xc0' \
             b'\x0c\x00\x01\x00\x01\x00\x00\x01\x92\x00\x04\x5b\xe4\x9b\x79'
        self.assertEqual(dnsclient.decode_rs(rs, 27),
                         ({'hostname': 'pikabu.ru',
                           'type': dnsclient.TYPE_A,
                           'class': dnsclient.CLASS_IN,
                           'TTL': 402, 'data_start': 39,
                           'data': b'\xd4\xe0p\xc1'}, 16))

    def test_decode_dns_message(self):
        rs = b'\x00\x01\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x06\x70\x69' \
             b'\x6b\x61\x62\x75\x02\x72\x75\x00\x00\x01\x00\x01\xc0\x0c\x00' \
             b'\x01\x00\x01\x00\x00\x01\x92\x00\x04\xd4\xe0\x70\xc1\xc0\x0c' \
             b'\x00\x01\x00\x01\x00\x00\x01\x92\x00\x04\x5b\xe4\x9b\x5e\xc0' \
             b'\x0c\x00\x01\x00\x01\x00\x00\x01\x92\x00\x04\x5b\xe4\x9b\x79'
        self.assertEqual({'additional_records': [],
                          'answers': [{'TTL': 402,
                                       'class': 1,
                                       'data': b'\xd4\xe0p\xc1',
                                       'data_start': 39,
                                       'hostname': 'pikabu.ru',
                                       'type': 1},
                                      {'TTL': 402,
                                       'class': 1,
                                       'data': b'[\xe4\x9b^',
                                       'data_start': 55,
                                       'hostname': 'pikabu.ru',
                                       'type': 1},
                                      {'TTL': 402,
                                       'class': 1,
                                       'data': b'[\xe4\x9by',
                                       'data_start': 71,
                                       'hostname': 'pikabu.ru',
                                       'type': 1}],
                          'authority_records': [],
                          'header': {'ancount': 3,
                                     'arcount': 0,
                                     'id': 1,
                                     'is_authoritative': 0,
                                     'is_response': 1,
                                     'nscount': 0,
                                     'opcode': 0,
                                     'qdcount': 1,
                                     'rcode': 0,
                                     'recursion_available': 1,
                                     'recursion_desired': 1,
                                     'trunc': 0},
                          'questions': [{'class': 1,
                                         'hostname': ('pikabu.ru', 11),
                                         'type': 1}]},
                         dnsclient.decode_dns_message(rs))


class DNSClientTests(unittest.TestCase):
    def setUp(self):
        self.client = dnsclient.DNSClient()

    def test_resolve_host(self):
        self.assertEqual(['213.196.34.228'],
                         self.client.hostname_to_ip("bash.im")["bash.im"])

    def test_resolve_host_ipv6(self):
        self.assertEqual(['2620:0:862:ed1a:0:0:0:1'],
                         self.client.hostname_to_ip("ru.wikipedia.org",
                                                    ipv6=True)[
                             "ru.wikipedia.org"])

    def test_resolve_host_non_recursive(self):
        self.assertEqual('213.196.34.228',
                         self.client.hostname_to_ip_non_recursive("bash.im")[
                             0][0])

    def test_resolve_host_non_recursive_ipv6(self):
        self.assertEqual('2620:0:862:ed1a:0:0:0:1',
                         self.client.hostname_to_ip_non_recursive(
                             "ru.wikipedia.org", ipv6=True)[0][0])
