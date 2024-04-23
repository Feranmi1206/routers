from scapy.fields import ByteField, ShortField, XIntField, LongField, ConditionalField, IPField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

import struct

HELLO_TYPE = 0x01
LSU_TYPE   = 0x04

class LSU(Packet):
    name = "LSU"
    fields_desc = [ IPField("subnet", "0.0.0.0"),
                    IPField("mask", "255.255.255.0"),
                    IPField("routerID", "0.0.0.0")]

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [
            ByteField("version", 2),
            ByteField("type", None),
            ShortField("length", None),
            IPField("routerID", None),
            XIntField("areaID", None),
            ShortField("checksum", None),
            ShortField("authType", 0),
            LongField("auth",0),

            ConditionalField(ShortField("helloInt", None), lambda pkt: pkt.type == HELLO_TYPE),

            ConditionalField(IPField("mask", None), lambda pkt: pkt.type == HELLO_TYPE),

            ConditionalField(ShortField("options", None), lambda pkt: pkt.type == HELLO_TYPE),

            ConditionalField(ShortField("seqNum", None), lambda pkt: pkt.type == LSU_TYPE),

            ConditionalField(ShortField("ttl", None), lambda pkt: pkt.type == LSU_TYPE),

            ConditionalField(XIntField("adverts", None), lambda pkt: pkt.type == LSU_TYPE),

            ConditionalField(PacketListField("advertisements", [], LSU, count_from=lambda pkt: pkt.adverts), lambda pkt: pkt.type == LSU_TYPE)]

bind_layers(IP, PWOSPF, proto=89)
bind_layers(PWOSPF,LSU,type=LSU_TYPE)
bind_layers(LSU, LSU)