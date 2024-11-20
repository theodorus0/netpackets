import struct
from enum import IntEnum
from typing import Optional

from netpackets import IPPacket
from netpackets.packet import Packet


class EtherType(IntEnum):
    IPv4 = 0x0800
    ARP = 0x0806
    RARP = 0x8035
    IPv6 = 0x86DD
    VLAN = 0x8100
    MPLS_UNICAST = 0x8847
    MPLS_MULTICAST = 0x8848
    JUMBO_FRAMES = 0x8870
    ETHERNET_FLOW_CONTROL = 0x8863
    ETHERNET_POWERLINK = 0x88AB
    LLDP = 0x88CC
    SERCOS_III = 0x88CD
    HOMEPLUG = 0x88E1
    EAP_OVER_LAN = 0x888E
    PROFINET = 0x8892
    HYPERSCSI = 0x889A
    ATA_OVER_ETHERNET = 0x88A2
    ETHERCAT = 0x88A4
    PROVIDER_BRIDGING = 0x88A8
    AVB_STREAMING = 0x88B6
    LLDP_MED = 0x88B8
    SERCOS_III_ALTERNATIVE = 0x88CD
    HOMEPLUG_GREEN_PHY = 0x88E1
    MRP = 0x88E3
    MAC_SECURITY = 0x88E5
    PTP = 0x88F7
    NCSI = 0x88F8
    PRP = 0x88FB
    CFM_OAM = 0x8902
    FCOE = 0x8906
    FIP = 0x8914
    QINQ = 0x9100


class EthernetFrame(Packet):
    def __init__(self, destination_mac, source_mac, ether_type, payload):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.ether_type: EtherType = ether_type
        self.payload = payload

    def build(self) -> bytes:
        dest_mac_bytes = bytes.fromhex(self.destination_mac.replace(':', ''))
        src_mac_bytes = bytes.fromhex(self.source_mac.replace(':', ''))
        ether_type_bytes = struct.pack('!H', self.ether_type)
        payload_bytes = self.payload
        return dest_mac_bytes + src_mac_bytes + ether_type_bytes + payload_bytes

    @staticmethod
    def parse(frame_bytes: bytes):
        dest_mac_bytes = frame_bytes[0:6]
        destination_mac = ':'.join(f'{b:02x}' for b in dest_mac_bytes)
        src_mac_bytes = frame_bytes[6:12]
        source_mac = ':'.join(f'{b:02x}' for b in src_mac_bytes)
        ether_type_bytes = frame_bytes[12:14]
        ether_type = struct.unpack('!H', ether_type_bytes)[0]
        payload = frame_bytes[14:]
        return EthernetFrame(destination_mac, source_mac, ether_type, payload)

    @property
    def sublayer(self) -> IPPacket:
        if self.ether_type != EtherType.IPv4:
            raise NotImplementedError(f"Can't decode {self.ether_type.name} protocol")
        return IPPacket.parse(self.payload)
