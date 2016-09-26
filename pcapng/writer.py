from __future__ import unicode_literals, division

from pcapng.blocks import (SimplePacket, SectionHeader, Block,
                           InterfaceDescription, NameResolution,
                           EnhancedPacket, InterfaceStatistics)
from pcapng.exceptions import InvalidStructure


class FileWriter(object):
    def __init__(self, stream, endianness='='):
        self.stream = stream
        self.endianness = endianness
        self._reset()

    def _reset(self):
        self.interface_count = 0
        self.current_section = None
        self.current_section_location = None
        self.current_section_size = None

    def _check_in_section(self):
        if self.current_section is None:
            raise InvalidStructure("No active section")

    def _write_in_section(self, block):
        assert isinstance(block, Block)
        self.current_section_size += block._write(self.stream)

    def flush(self):
        self.stream.flush()

    def begin_section(self, **kwargs):
        if self.current_section is not None:
            raise InvalidStructure("A section is already active")
        self.current_section_location = self.stream.tell()
        self.current_section = (SectionHeader
                                .from_dict(self.endianness, **kwargs))
        self.current_section._write(self.stream)
        self.current_section_size = 0

    def end_section(self, flush=True, write_length=True):
        self._check_in_section()
        if write_length:
            # go back to section header to write the length we know now
            current_location = self.stream.tell()
            self.stream.seek(self.current_section_location)
            self.current_section.section_length = self.current_section_size
            self.current_section._write(self.stream)
            self.stream.seek(current_location)
        if flush:
            self.flush()
        self._reset()

    def write_simple_packet(self, **kwargs):
        self._check_in_section()
        self._write_in_section(SimplePacket
                               .from_dict(self.current_section, **kwargs))

    def write_enhanced_packet(self, **kwargs):
        self._check_in_section()
        self._write_in_section(EnhancedPacket
                               .from_dict(self.current_section, **kwargs))

    def write_interface(self, **kwargs):
        self._check_in_section()
        interface = (InterfaceDescription
                     .from_dict(self.current_section, **kwargs))
        interface_id = self.current_section.register_interface(interface)
        self._write_in_section(interface)
        return interface_id

    def write_interface_statistics(self, **kwargs):
        self._check_in_section()
        self._write_in_section(InterfaceStatistics
                               .from_dict(self.current_section, **kwargs))

    def write_name_resolution(self, **kwargs):
        self._check_in_section()
        self._write_in_section(NameResolution
                               .from_dict(self.current_section, **kwargs))
