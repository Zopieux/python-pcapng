from __future__ import unicode_literals, division

import six

from pcapng.utils import (
    unpack_ipv4, unpack_ipv6, unpack_macaddr, unpack_euiaddr,
    unpack_timestamp_resolution, pack_timestamp_resolution,
    uint64_to_timestamp, timestamp_to_uint64)
import ipaddress


def test_unpack_ipv4():
    assert unpack_ipv4(b'\x00\x00\x00\x00') == \
        ipaddress.IPv4Address('0.0.0.0')
    assert unpack_ipv4(b'\xff\xff\xff\xff') == \
        ipaddress.IPv4Address('255.255.255.255')
    assert unpack_ipv4(b'\x0a\x10\x20\x30') == \
        ipaddress.IPv4Address('10.16.32.48')


def test_unpack_ipv6():
    assert unpack_ipv6(b'\x00\x11\x22\x33\x44\x55\x66\x77'
                       b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff') \
        == ipaddress.IPv6Address('0011:2233:4455:6677:8899:aabb:ccdd:eeff')


def test_unpack_macaddr():
    assert unpack_macaddr(b'\x00\x11\x22\xaa\xbb\xcc') == '00:11:22:aa:bb:cc'


def test_unpack_euiaddr():
    assert unpack_euiaddr(b'\x00\x11\x22\x33\xaa\xbb\xcc\xdd') == \
           '00:11:22:33:aa:bb:cc:dd'


def test_unpack_tsresol():
    assert unpack_timestamp_resolution(chr(0)) == 1
    assert unpack_timestamp_resolution(chr(1)) == 1e-1
    assert unpack_timestamp_resolution(chr(6)) == 1e-6
    assert unpack_timestamp_resolution(chr(100)) == 1e-100

    assert unpack_timestamp_resolution(chr(0 | 0b10000000)) == 1
    assert unpack_timestamp_resolution(chr(1 | 0b10000000)) == 2 ** -1
    assert unpack_timestamp_resolution(chr(6 | 0b10000000)) == 2 ** -6
    assert unpack_timestamp_resolution(chr(100 | 0b10000000)) == 2 ** -100


def test_pack_tsresol():
    def test(base, exp, expected):
        result = next(six.iterbytes(pack_timestamp_resolution(base, exp)))
        assert result == expected

    test(10, 0b00000000, 0b00000000)
    test(10, 0b00000011, 0b00000011)
    test(10, 0b00000100, 0b00000100)
    test(10, 0b00111100, 0b00111100)

    test(2, 0b00000000, 0b10000000)
    test(2, 0b00000011, 0b10000011)
    test(2, 0b00000100, 0b10000100)
    test(2, 0b00111100, 0b10111100)


def test_timestamp_to_uint64():
    for resolution in (1e-6, 1e-9):
        for ts in (0, 0xf, 0xff, 0xffff, 0xffffffff, 0xffffffffffff):
            high, low = timestamp_to_uint64(ts, resolution)
            ts2 = uint64_to_timestamp(high, low, resolution)
            assert abs(ts - ts2) < 1
