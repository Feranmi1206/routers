from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from threading import Timer
from ipaddress  import ip_network, ip_address, IPv4Address
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

class MacLearningController(Thread):
    def __init__(self, sw, ips, macs, subnets, area_id=1, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.subnets = subnets
        self.stop_event = Event()

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port


    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handlePkt(self, pkt):
        #pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)


class ArpCache:
    def __init__(self, sw, timeout=120):
        self.sw = sw
        self.arp_entries = {}
        self.timers = {}

    def in_cache(self, ip):
        return (ip in self.arp_entries.keys())

    def add_entry(self, ip, mac):
        print("Adding new ARP entry {} --> {}".format(ip, mac))
        self.arp_entries[ip] = mac

        timer = Timer(120, self.remove_entry, args=[ip, mac])
        self.timers[ip] = timer
        timer.start()
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip_addr': ip},
                action_name='MyIngress.arp_match',
                action_params={'dst_mac_addr': mac},
                priority = 1)

    def remove_entry(self, ip, mac):
        print("Removing ARP entry {} --> {}".format(ip, mac))


        self.sw.removeTableEntry(table_name='MyIngress.arp_table',
            match_fields={'next_hop_ip_addr': ip},
            action_name='MyIngress.arp_match',
            action_params={'dst_mac_addr': mac},
            priority = 1)

        del self.entries[ip]





class Controller(Thread):
    def __init__(self, sw, ips, macs, subnets, area_id=1, start_wait=0.3):
        super(Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.stop_event = Event()

        self.arp_cache = ArpCache(sw)
        self.pkt_cache = {}

        self.subnets = subnets
        self.ips = ips
        self.macs = macs

        self.area_id = area_id

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        print("Adding new MAC address entry {} --> {}".format(mac, port))

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def addArpEntry(self, ip, mac):
        if self.arp_cache.in_cache(ip):
            return

        if any(ip_address(ip) in ip_network(subnet) for subnet in self.subnets):
            self.arp_cache.add_entry(ip, mac)

    def handleArpReply(self, pkt):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpEntry(src_ip, pkt[ARP].hwsrc)

        if dst_ip in self.ips:
            if src_ip not in self.pkt_cache:
                if not self.arp_cache.in_cache(src_ip):
                    print("Arp request failure")
                return

            pkt_upd = self.pkt_cache[src_ip]
            pkt_upd[Ether].dst = pkt[Ether].dst
            self.send(self.pkt_cache[src_ip])
            del self.pkt_cache[src_ip]

        self.send(pkt)

    def handleArpRequest(self, pkt):

        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        if src_ip in self.ips:
            return

        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpEntry(src_ip, pkt[ARP].hwsrc)

        try:
            idx, subnet = next((num, s) for num, s in enumerate(self.subnets) if ip_address(dst_ip) in ip_network(s))
        except StopIteration:
            subnet = None
            idx = None

        if subnet:
            if dst_ip in self.ips:
                pkt[Ether].src = self.macs[idx]
                pkt[Ether].dst = pkt[Ether].src
                pkt[ARP].op = ARP_OP_REPLY
                pkt[ARP].hwdst = pkt[ARP].hwsrc
                pkt[ARP].pdst = pkt[ARP].psrc
                pkt[ARP].hwsrc = self.macs[idx]
                pkt[ARP].psrc = dst_ip

            self.send(pkt)

    def sendArpRequest(self, pkt, ip):

        try:
                idx = next(num for num, s in enumerate(self.subnets) if ip_address(ip) in ip_network(s))
        except StopIteration:
            idx = None

        src_mac = self.macs[idx]
        src_ip = self.ips[idx]
        src_port = pkt[CPUMetadata].srcPort

        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / CPUMetadata(srcPort=src_port) / ARP(
            hwsrc=src_mac, psrc=src_ip, pdst=ip, hwdst="00:00:00:00:00:00",
            op=ARP_OP_REQ, hwlen=6, plen=4, hwtype=1, ptype = 0x800)

        self.pkt_cache[ip] = pkt
        self.send(arp_req)