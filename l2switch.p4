/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4         = 0x800;

const bit<8> PWOSPF_VER         = 0x2;
const bit<8> HELLO_TYPE         = 0x1;
const bit<8> LSU_TYPE           = 0x4;
const bit<8> PWOSPF_PROT        = 0x59;

const bit<32> ALLSPFRouters = 0xe0000005;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header pwospf_hdr_t {
    bit<8> version;
    bit<8> type;
    bit<16> length;
    bit<32> routerID;
    bit<32> areaID;
    bit<16> checksum;
    bit<16> authType;
    bit<64> auth;
}

header pwospf_hello_hdr_t {
    bit<16> helloInt;
    bit<32> mask;
    bit<16> options;
}

header lsu_hdr_t {
    bit<16> seqNum;
    bit<16> ttl;
    bit<32> adverts;
}

header lsu_advert_t {
    varbit<960> content;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t           ethernet;
    cpu_metadata_t       cpu_metadata;
    arp_t                arp;
    ipv4_t               ipv4;
    pwospf_hdr_t         pwospf_hdr;
    pwospf_hello_hdr_t   pwospf_hello_hdr;
    lsu_hdr_t            lsu_hdr;
    lsu_advert_t      lsu_advert;
}

error {Invalid_PWOSPF}
struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PWOSPF_PROT: parse_pwospf_hdr;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_pwospf_hdr{
        packet.extract(hdr.pwospf_hdr);
        transition select(hdr.pwospf_hdr.type){
            HELLO_TYPE: parse_pwospf_hello_hdr;
            LSU_TYPE: parse_lsu_hdr;
            default: accept;
        }
    }

    state parse_pwospf_hello_hdr{
        packet.extract(hdr.pwospf_hello_hdr);
        transition accept;
   }

   state parse_lsu_hdr{
        packet.extract(hdr.lsu_hdr);
        verify(hdr.lsu_hdr.adverts >= 1, error.Invalid_PWOSPF);
        transition parse_lsu_advert;
   }

   state parse_lsu_advert{
    packet.extract(hdr.lsu_advert,(bit<32>)(hdr.lsu_hdr.adverts * 32));
    transition accept;
   }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    ip4Addr_t next_hop_ip_addr;

    // COUNTERS

    counter(1, CounterType.packets) count_ip_packets;
    counter(1, CounterType.packets) count_arp_packets;
    counter(1, CounterType.packets) count_cpu_packets;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ipv4_forward(macAddr_t dstAddr, port_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action arp_match(macAddr_t dst_mac_addr) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac_addr;
    }

    action set_next_hop(ip4Addr_t next_hop) {
        next_hop_ip_addr = next_hop;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            set_next_hop;
            send_to_cpu;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table arp_table {
        key = {
            next_hop_ip_addr: ternary;
        }
        actions = {
            send_to_cpu;
            arp_match;
            NoAction;

        }
        size = 1024;
        default_action = send_to_cpu();
    }


    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
            send_to_cpu;
        }
        size = 1024;
        default_action = drop();
    }


    apply {

        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if(hdr.pwospf_hello_hdr.isValid()){
            if(standard_metadata.ingress_port == CPU_PORT){
                fwd_l2.apply();
            }
            else{
                send_to_cpu();
            }
        }
        else if(hdr.lsu_hdr.isValid() && standard_metadata.ingress_port != CPU_PORT){
            send_to_cpu();
        }

        else if (hdr.ipv4.isValid()) {

            if (routing_table.apply().hit) {
                if (arp_table.apply().hit) {
                    fwd_l2.apply();
                }
            }
        }

        else if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        }
        else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.pwospf_hdr);
        packet.emit(hdr.pwospf_hello_hdr);
        packet.emit(hdr.lsu_hdr);
        packet.emit(hdr.lsu_advert);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;