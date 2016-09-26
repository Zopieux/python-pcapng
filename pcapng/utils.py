from __future__ import unicode_literals, division

import struct

import io
import ipaddress
import six


def unpack_ipv4(data):
    return ipaddress.IPv4Address(bytes(data))


def pack_ipv4(data):
    return ipaddress.IPv4Address(data).packed


def unpack_ipv6(data):
    return ipaddress.IPv6Address(bytes(data))


def pack_ipv6(data):
    return ipaddress.IPv6Address(data).packed


def unpack_macaddr(data):
    return ':'.join('{:02x}'.format(x) for x in six.iterbytes(data))


def pack_macaddr(data):
    return b''.join(six.int2byte(int(x, 16)) for x in data.split(':'))


def unpack_euiaddr(data):
    return unpack_macaddr(data)


def pack_euiaddr(data):
    return pack_macaddr(data)


def unpack_custom_option(data, endianness):
    from pcapng.structs import read_int, read_bytes_padded
    buf = io.BytesIO(data)
    pen = read_int(buf, 32, False, endianness=endianness)
    data = read_bytes_padded(buf, len(data) - 4)
    return (pen, data)


def pack_custom_option(data, endianness):
    from pcapng.structs import write_int, write_bytes_padded
    pen, payload = data
    buf = io.BytesIO()
    write_int(buf, pen, 32, False, endianness=endianness)
    write_bytes_padded(buf, payload)
    return buf.getvalue()


def unpack_timestamp_resolution(data):
    """
    Unpack a timestamp resolution.

    Returns a floating point number representing the timestamp
    resolution (multiplier).
    """
    if len(data) != 1:
        raise ValueError('Data must be exactly one byte')
    num = ord(data)
    base = 2 if (num >> 7 & 1) else 10
    exponent = num & 0b01111111
    return base ** (-exponent)


def pack_timestamp_resolution(base, exponent):
    """
    Pack a timestamp resolution.

    :param base: 2 or 10
    :param exponent: negative power of the base to be encoded
    """
    exponent = abs(exponent)
    if base == 2:
        return struct.pack('B', exponent | 0b10000000)
    if base == 10:
        return struct.pack('B', exponent)
    raise ValueError('Supported bases are: 2, 10')


def timestamp_to_uint64(ts, resolution):
    ts = int(ts / resolution)
    high = ts >> 32
    low = ts & 0xffffffff
    return high, low


def uint64_to_timestamp(high, low, resolution):
    return ((high << 32) + low) * resolution
