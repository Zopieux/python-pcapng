from __future__ import absolute_import, division, unicode_literals

import io

import pytest
import subprocess

from pcapng.constants.link_types import LINKTYPE_ETHERNET
from pcapng.exceptions import InvalidStructure
from pcapng.writer import FileWriter

HTTP_PAYLOAD = (
    b'\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00'
    b'E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97'  # IP
    b'\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 '  # TCP
    b'\x00\xbb9\x00\x00'  # TCP(cont)
    b'GET /index.html HTTP/1.0 \n\n'  # HTTP
)


class file_writer(object):
    def __init__(self, check=True, extract=None, write_to=None):
        self.check = check
        self.extract = extract or {}
        self.write_to = write_to
        self.extracted = []

    def __enter__(self):
        self.io = io.BytesIO()
        self.fw = FileWriter(self.io)
        return self.fw

    def __exit__(self, exc_type, exc_val, exc_tb):
        data = self.io.getvalue()
        print(data)
        if self.write_to:
            with open(self.write_to, 'wb') as f:
                f.write(data)
        fields = list(self.extract.items())
        if self.check:
            # -Nn network name resolution (to test NameResolution blocks)
            # -r- read from stdin
            cmd = ['tshark', '-Nn', '-r', '-']
            if self.extract:
                cmd += ['-T', 'fields']
                cmd += ['-e' + field for field, value in fields]
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate(data)
            if self.extract:
                result = stdout.decode().strip().split('\t')
                for (field, expected), actual in zip(fields, result):
                    assert actual == expected
            assert p.returncode == 0, stderr


def test_write_without_section_header():
    with file_writer(check=False) as writer:
        with pytest.raises(InvalidStructure):
            writer.write_simple_packet(payload=HTTP_PAYLOAD)

        with pytest.raises(InvalidStructure):
            writer.write_name_resolution()


def test_end_section_without_section_header():
    with file_writer(check=False) as writer:
        with pytest.raises(InvalidStructure):
            writer.end_section()


def test_begin_session_twice():
    with file_writer(check=False) as writer:
        writer.begin_section()
        with pytest.raises(InvalidStructure):
            writer.begin_section()


def test_write_empty():
    with file_writer() as writer:
        writer.begin_section()
        writer.end_section()


def test_write_session_options():
    with file_writer(write_to='/tmp/section-options.pcapng') as writer:
        writer.begin_section(options={'shb_os': b'Debian 8 (Jessie)',
                                      'shb_hardware': b'Much hardware'})
        writer.end_section()


def test_write_name_resolution():
    with file_writer(extract={'ip.src_host': 'example.org',
                              'ip.dst_host': 'other.com'}) as writer:
        writer.begin_section()
        writer.write_name_resolution(records=[
            {'type': 1, 'name': 'example.org', 'address': '192.168.5.21'},
            {'type': 1, 'name': 'other.com', 'address': '66.35.250.151'},
        ])
        writer.write_interface(link_type=LINKTYPE_ETHERNET, snaplen=0xffffffff)
        writer.write_simple_packet(payload=HTTP_PAYLOAD)
        writer.end_section()


def test_write_without_interface():
    with file_writer() as writer:
        writer.begin_section()
        with pytest.raises(InvalidStructure):
            writer.write_simple_packet(payload=HTTP_PAYLOAD)
        writer.end_section()


def test_write_interface():
    with file_writer() as writer:
        writer.begin_section()
        writer.write_interface(link_type=LINKTYPE_ETHERNET, snaplen=0xffffffff)
        writer.end_section()


def test_write_simple_packet_multiple_interfaces():
    with file_writer() as writer:
        writer.begin_section()
        writer.write_interface(link_type=LINKTYPE_ETHERNET, snaplen=0xffffffff)
        writer.write_interface(link_type=LINKTYPE_ETHERNET, snaplen=0xffffffff)
        with pytest.raises(InvalidStructure):
            writer.write_simple_packet(payload=HTTP_PAYLOAD)


def test_write_simple_packet():
    with file_writer(extract={'http.request.uri': '/index.html',
                              'http.request.method': 'GET'}) as writer:
        writer.begin_section()
        writer.write_interface(link_type=LINKTYPE_ETHERNET, snaplen=0xffffffff)
        writer.write_simple_packet(payload=HTTP_PAYLOAD)
        writer.end_section()


def test_write_enhanced_packet_invalid_interface():
    with file_writer() as writer:
        writer.begin_section()
        iface = writer.write_interface(link_type=LINKTYPE_ETHERNET,
                                       snaplen=0xffffffff)
        with pytest.raises(InvalidStructure):
            writer.write_enhanced_packet(interface=iface + 1, timestamp=123456,
                                         payload=HTTP_PAYLOAD)


def test_write_enhanced_packet():
    with file_writer(extract={'http.request.uri': '/index.html',
                              'http.request.method': 'GET',
                              'frame.time_epoch': '123456.000000000'},
                     write_to='/tmp/enhanced.pcapng') as writer:
        writer.begin_section()
        iface = writer.write_interface(link_type=LINKTYPE_ETHERNET,
                                       snaplen=0xffffffff)
        writer.write_enhanced_packet(interface=iface, timestamp=123456,
                                     payload=HTTP_PAYLOAD,
                                     options={'opt_comment': 'hello world!',
                                              'opt_custom_rw_binary': (0xcafebabe, b'\x01\xDE\xAD\xBE')})
        writer.write_interface_statistics(interface=iface,
                                          timestamp=123456)
        writer.end_section()


if __name__ == '__main__':
    test_write_session_options()
