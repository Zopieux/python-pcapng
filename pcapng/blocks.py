from __future__ import unicode_literals, division

import six

"""
Module containing the definition of known / supported "blocks" of the
pcap-ng format.

Each block is a struct-like object with some fields and possibly
a variable amount of "items" (usually options).

They can optionally expose some other properties, used eg. to provide
better access to decoded information, ...
"""

import io
import itertools

from pcapng.structs import (
    struct_decode, RawBytes, IntField, OptionsField, PacketDataField,
    ListField, NameResolutionRecordField, SimplePacketDataField, struct_encode,
    write_int, write_bytes, BYTE_ORDER_MAGIC)
from pcapng.constants import link_types
from pcapng.exceptions import InvalidStructure
from pcapng.utils import unpack_timestamp_resolution, uint64_to_timestamp, \
    timestamp_to_uint64

KNOWN_BLOCKS = {}


class Block(object):
    """Base class for blocks"""

    schema = []

    def __init__(self):
        self._raw = None
        self._decoded = None

    @classmethod
    def from_context(cls, raw):
        raise NotImplementedError()

    @classmethod
    def from_dict(cls, data):
        raise NotImplementedError()

    def _decode(self):
        return struct_decode(self.schema, io.BytesIO(self._raw),
                             self.endianness)

    def _encode(self, stream):
        return struct_encode(self.schema, self, stream, self.endianness)

    def _write(self, stream):
        buffer = io.BytesIO()
        size = self._encode(buffer)
        size += 4 + 4 + 4  # type, total length x 2
        assert size % 4 == 0
        # type
        write_int(stream, self.magic_number, 32, False, self.endianness)
        # total length
        write_int(stream, size, 32, False, self.endianness)
        # body
        write_bytes(stream, buffer.getvalue())
        # total length (bis)
        write_int(stream, size, 32, False, self.endianness)
        return size

    @property
    def endianness(self):
        raise NotImplementedError()

    def __setattr__(self, key, value):
        for name, field in self.schema:
            if key == name:
                if self._decoded is None:
                    self._decoded = {}
                self._decoded[key] = value
                return
        super(Block, self).__setattr__(key, value)

    def __getattr__(self, name):
        if self._decoded is None:
            self._decoded = self._decode()
        try:
            return self._decoded[name]
        except KeyError:
            raise AttributeError(name)

    def __repr__(self):
        args = []
        for item in self.schema:
            name = item[0]
            value = getattr(self, name)
            try:
                value = repr(value)
            except Exception:
                value = '<{0} (repr failed)>'.format(type(value).__name__)
            args.append('{0}={1}'.format(name, value))
        return '<{0} {1}>'.format(self.__class__.__name__, ' '.join(args))


class SectionMemberBlock(Block):
    def __init__(self, section):
        super(SectionMemberBlock, self).__init__()
        assert isinstance(section, SectionHeader)
        self.section = section

    @classmethod
    def from_context(cls, raw, ctx):
        inst = cls(section=ctx.current_section)
        inst._raw = raw
        return inst

    @property
    def endianness(self):
        return self.section.endianness


def register_block(block):
    """Handy decorator to register a new known block type"""
    KNOWN_BLOCKS[block.magic_number] = block
    return block


@register_block
class SectionHeader(Block):
    magic_number = 0x0a0d0d0a
    schema = [
        ('version_major', IntField(16, False)),
        ('version_minor', IntField(16, False)),
        ('section_length', IntField(64, True)),
        ('options', OptionsField([
            (2, 'shb_hardware', 'string'),
            (3, 'shb_os', 'string'),
            (4, 'shb_userappl', 'string'),
        ]))]

    def __init__(self, endianness):
        super(SectionHeader, self).__init__()
        self._endianness = endianness
        self._interfaces_id = itertools.count(0)
        self.interfaces = {}
        self.interface_stats = {}

    @classmethod
    def from_raw(cls, raw, endianness):
        inst = cls(endianness)
        inst._raw = raw
        return inst

    @classmethod
    def from_dict(cls, endianness, version_major=1, version_minor=0, options=None):
        inst = cls(endianness)
        inst.section_length = -1
        inst.version_major = version_major
        inst.version_minor = version_minor
        inst.options = options or {}
        return inst

    @property
    def endianness(self):
        return self._endianness

    def register_interface(self, interface):
        """Helper method to register an interface within this section"""
        assert isinstance(interface, InterfaceDescription)
        interface_id = next(self._interfaces_id)
        interface.interface_id = interface_id
        self.interfaces[interface_id] = interface
        return interface_id

    def add_interface_stats(self, interface_stats):
        """Helper method to register interface stats within this section"""
        assert isinstance(interface_stats, InterfaceStatistics)
        self.interface_stats[interface_stats.interface_id] = interface_stats

    def _encode(self, stream):
        # write byte-order magic
        size = write_int(stream, BYTE_ORDER_MAGIC, 32, False, self.endianness)
        size += super(SectionHeader, self)._encode(stream)
        return size

    @property
    def version(self):
        return (self.version_major, self.version_minor)

    @property
    def length(self):
        return self.section_length

    def __repr__(self):
        return ('<{name} version={version} endianness={endianness} '
                'length={length} options={options}>').format(
            name=self.__class__.__name__,
            version='.'.join(str(x) for x in self.version),
            endianness=repr(self._endianness),
            length=self.length,
            options=repr(self.options))


@register_block
class InterfaceDescription(SectionMemberBlock):
    magic_number = 0x00000001
    schema = [
        ('link_type', IntField(16, False)),  # todo: enc/decode
        ('reserved', RawBytes(2)),
        ('snaplen', IntField(32, False)),
        ('options', OptionsField([
            (2, 'if_name', 'string'),
            (3, 'if_description', 'string'),
            (4, 'if_IPv4addr', 'ipv4+mask'),
            (5, 'if_IPv6addr', 'ipv6+prefix'),
            (6, 'if_MACaddr', 'macaddr'),
            (7, 'if_EUIaddr', 'euiaddr'),
            (8, 'if_speed', 'u64'),
            (9, 'if_tsresol'),  # Just keep the raw data
            (10, 'if_tzone', 'u32'),
            (11, 'if_filter', 'string'),
            (12, 'if_os', 'string'),
            (13, 'if_fcslen', 'u8'),
            (14, 'if_tsoffset', 'i64'),
        ]))]

    @classmethod
    def from_dict(cls, section, link_type, snaplen, options=None):
        inst = cls(section)
        inst.reserved = b'\x00\x00'
        inst.link_type = link_type
        inst.snaplen = snaplen
        inst.options = options or {}
        return inst

    @property  # todo: cache this property
    def timestamp_resolution(self):
        # ------------------------------------------------------------
        # Resolution of timestamps. If the Most Significant Bit is
        # equal to zero, the remaining bits indicates the resolution
        # of the timestamp as as a negative power of 10 (e.g. 6 means
        # microsecond resolution, timestamps are the number of
        # microseconds since 1/1/1970). If the Most Significant Bit is
        # equal to one, the remaining bits indicates the resolution as
        # as negative power of 2 (e.g. 10 means 1/1024 of second). If
        # this option is not present, a resolution of 10^-6 is assumed
        # (i.e. timestamps have the same resolution of the standard
        # 'libpcap' timestamps).
        # ------------------------------------------------------------

        if 'if_tsresol' in (self.options or {}):
            return unpack_timestamp_resolution(self.options['if_tsresol'])

        return 1e-6

    @property
    def statistics(self):
        # todo: ensure we always have an interface id -> how??
        return self.section.interface_stats.get(self.interface_id)

    @property
    def link_type_description(self):
        try:
            return link_types.LINKTYPE_DESCRIPTIONS[self.link_type]
        except KeyError:
            return 'Unknown link type: 0x{0:04x}'.format(self.link_type)


class BlockWithTimestampMixin(object):
    """
    Block mixin adding properties to better access timestamps
    of blocks that provide one.
    """

    @property
    def timestamp(self):
        # First, get the accuracy from the ts_resol option
        return uint64_to_timestamp(self.timestamp_high,
                                   self.timestamp_low,
                                   self.timestamp_resolution)

    @timestamp.setter
    def timestamp(self, ts):
        self.timestamp_high, self.timestamp_low = \
            timestamp_to_uint64(ts, self.timestamp_resolution)

    @property
    def timestamp_resolution(self):
        return self.interface.timestamp_resolution

        # todo: add some property returning a datetime() with timezone..


class BlockWithInterfaceMixin(object):
    def _check_interface_is_valid(self):
        if self.interface_id not in self.section.interfaces:
            raise InvalidStructure("interface {} does not exist in section"
                                   .format(self.interface_id))

    @property
    def interface(self):
        # We need to get the correct interface from the section
        # by looking up the interface_id
        return self.section.interfaces[self.interface_id]


class BasePacketBlock(
    SectionMemberBlock,
    BlockWithInterfaceMixin,
    BlockWithTimestampMixin):
    """Base class for the "EnhancedPacket" and "Packet" blocks"""

    @staticmethod
    def _parse_payload(data):
        if not isinstance(data, (list, tuple)):
            # assume non-truncated
            data = (len(data), data)
        length, payload = data
        assert isinstance(length, six.integer_types)
        assert isinstance(payload, six.binary_type)
        return (length, payload)


@register_block
class EnhancedPacket(BasePacketBlock):
    magic_number = 0x00000006
    schema = [
        ('interface_id', IntField(32, False)),
        ('timestamp_high', IntField(32, False)),
        ('timestamp_low', IntField(32, False)),
        ('packet_payload_info', PacketDataField()),
        ('options', OptionsField([
            (2, 'epb_flags'),  # todo: is this endianness dependent?
            (3, 'epb_hash'),  # todo: process the hash value
            (4, 'epb_dropcount', 'u64'),
        ]))
    ]

    @classmethod
    def from_dict(cls, section, interface, payload, timestamp, options=None):
        inst = cls(section)
        inst.interface_id = interface
        inst._check_interface_is_valid()
        assert isinstance(timestamp, six.integer_types)
        inst.timestamp = timestamp
        inst.options = options or {}
        inst.packet_payload_info = cls._parse_payload(payload)
        return inst

    @property
    def packet_len(self):
        return self.packet_payload_info[0]

    @property
    def packet_data(self):
        return self.packet_payload_info[1]

    @property
    def captured_len(self):
        return len(self.packet_data)


@register_block
class SimplePacket(SectionMemberBlock):
    magic_number = 0x00000003
    schema = [
        ('packet_simple_payload_info', SimplePacketDataField()),
    ]

    @classmethod
    def from_dict(cls, section, payload):
        inst = cls(section)
        # interface validity checks
        if not 0 in section.interfaces:
            raise InvalidStructure("Simple Packet block written before any "
                                   "Interface Description block")
        if len(section.interfaces) != 1:
            raise InvalidStructure("Simple Packet written in a section with "
                                   "multiple Interface Description blocks")
        assert isinstance(payload, six.binary_type)
        inst.packet_simple_payload_info = payload
        return inst

    @property
    def packet_data(self):
        return self.packet_simple_payload_info

    @property
    def packet_len(self):
        return len(self.packet_data)


@register_block
class Packet(BasePacketBlock):
    # OBSOLETE BLOCK
    magic_number = 0x00000002
    schema = [
        ('interface_id', IntField(16, False)),
        ('drops_count', IntField(16, False)),
        ('timestamp_high', IntField(32, False)),
        ('timestamp_low', IntField(32, False)),
        ('packet_payload_info', PacketDataField()),
        ('options', OptionsField([
            (2, 'epb_flags', 'u32'),  # A flag!
            (3, 'epb_hash'),  # Variable size!
        ]))
    ]

    @classmethod
    def from_dict(cls, section, interface, drops_count, timestamp, payload, options=None):
        inst = cls(section)
        inst.interface_id = interface
        inst._check_interface_is_valid()
        inst.drops_count = drops_count
        inst.timestamp = timestamp
        inst.options = options or {}
        inst.packet_payload_info = cls._parse_payload(payload)
        return inst

    @property
    def packet_len(self):
        return self.packet_payload_info[0]

    @property
    def packet_data(self):
        return self.packet_payload_info[1]

    @property
    def captured_len(self):
        return len(self.packet_data)


@register_block
class NameResolution(SectionMemberBlock):
    magic_number = 0x00000004
    schema = [
        ('records', ListField(NameResolutionRecordField())),
        ('options', OptionsField([
            (2, 'ns_dnsname', 'string'),
            (3, 'ns_dnsIP4addr', 'ipv4'),
            (4, 'ns_dnsIP6addr', 'ipv6'),
        ])),
    ]

    @classmethod
    def from_dict(cls, section, records, options=None):
        inst = cls(section)
        inst.records = list(records)
        inst.options = options or {}
        return inst


@register_block
class InterfaceStatistics(SectionMemberBlock, BlockWithTimestampMixin,
                          BlockWithInterfaceMixin):
    magic_number = 0x00000005
    schema = [
        ('interface_id', IntField(32, False)),
        ('timestamp_high', IntField(32, False)),
        ('timestamp_low', IntField(32, False)),
        ('options', OptionsField([
            (2, 'isb_starttime', 'u64'),  # todo: consider resolution
            (3, 'isb_endtime', 'u64'),
            (4, 'isb_ifrecv', 'u64'),
            (5, 'isb_ifdrop', 'u64'),
            (6, 'isb_filteraccept', 'u64'),
            (7, 'isb_osdrop', 'u64'),
            (8, 'isb_usrdeliv', 'u64'),
        ])),
    ]

    @classmethod
    def from_dict(cls, section, interface, timestamp, options=None):
        inst = cls(section)
        inst.interface_id = interface
        inst._check_interface_is_valid()
        inst.timestamp = timestamp
        inst.options = options or {}
        return inst


class UnknownBlock(Block):
    """
    Class used to represent an unknown block.

    Its block type and raw data will be stored directly with no further
    processing.
    """

    def __init__(self, block_type, data):
        super(UnknownBlock, self).__init__()
        self.block_type = block_type
        self.data = data

    def __repr__(self):
        return ('UnknownBlock(0x{0:08X}, {1!r})'
                .format(self.block_type, self.data))
