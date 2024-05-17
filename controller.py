from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import PWOSPF, LSU
from ipaddress  import ip_network, ip_address, IPv4Address
import time, threading
import heapq
from collections import defaultdict, deque

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
MASK = 0xFFFFFFFF
MASK_2 = 0xFFFFFF00
HELLO_INT = 0x5
HELLO_TYPE = 0x1
LSU_TYPE = 0x4
TTL_DEFAULT = 0x1e

ALLSPFRouters = "224.0.0.5"

class ARPEntry:
    def __init__(self, ip, mac, timer):
        self.ip = ip
        self.mac = mac
        self.timer = timer
        self.timer.start()

class ARPCache:
    def __init__(self, sw, timeout=120):
        self.sw = sw
        self.cache = {}
        self.timeout = timeout

    def add_entry(self, ip, mac):
        self.cache[ip] = ARPEntry(ip, mac, threading.Timer(self.timeout, self.entry_timeout, args=[ip, mac]))

        print("New ARP entry {} --> {}".format(ip, mac))

        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip_addr': [ip, MASK]},
                action_name='MyIngress.arp_match',
                action_params={'dst_mac_addr': mac},
                priority = 1)

    def lookup(self, ip):
        entry = self.cache.get(ip)
        if entry:
            return entry.ip, entry.mac
        return None

    def delete_entry(self, ip, mac):
        if ip in self.cache:
            del self.cache[ip]

            print("Deleting ARP entry {} --> {}".format(ip, mac))

            self.sw.removeTableEntry(table_name='MyIngress.arp_table',
            match_fields={'next_hop_ip_addr': [ip, MASK]},
            action_name='MyIngress.arp_match',
            action_params={'dst_mac_addr': mac},
            priority = 1)

    def entry_timeout(self, ip, mac):

        self.delete_entry(ip, mac)

class OSPFInterface:
    def __init__(self, ip, subnet, helloInt, routerID, areaID):
        self.ip = ip
        self.subnet = ip_network(subnet)
        self.mask = self.subnet.netmask
        self.helloInt = helloInt
        self.routerID = routerID
        self.areaID = areaID
        self.timers = {}
        self.flag = False
        self.neighbours = []

    def update_timer(self, neighbourID, neighbourIP):
        timer_info = self.timers.get(neighbourIP)
        if timer_info:
            timer, _ = timer_info
            timer.cancel()
        else:
            self.neighbours.append((neighbourIP, neighbourID))
            self.flag = True

        timer = threading.Timer(3 * self.helloInt, self.handle_timer_expiration, args=[neighbourIP, neighbourID])
        self.timers[neighbourIP] = (timer, neighbourID)
        timer.start()

    def handle_timer_expiration(self, neighbourIP, neighbourID):
        print(f"Timeout on {neighbourIP}")
        self.neighbours.remove((neighbourIP, neighbourID))
        del self.timers[neighbourIP]
        self.flag = True

    def is_lsu_needed(self):
        result = self.flag
        self.flag = False
        return result

    def build_hello_packet(self, src_mac):
        ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        cpumetadata = CPUMetadata(origEtherType=0x0800, srcPort=1)
        ipv4 = IP(src=self.ip, dst=ALLSPFRouters)  #
        ospf = PWOSPF(type=1, routerID=self.routerID, areaID=self.areaID, mask=self.mask, helloInt=self.helloInt)
        return ether / cpumetadata / ipv4 / ospf

class Controller(Thread):
    def __init__(self, sw, ips, macs, subnets, routerID, areaID=1, start_wait=0.3, lsuInt=10):
        super(Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.stop_event = Event()
        self.sequence = 0

        self.arp_cache = ARPCache(sw)
        self.pkt_cache = {}

        self.subnets = subnets
        self.ips = ips
        self.macs = macs

        self.routerID = routerID
        self.areaID = areaID

        self.lsuInt = lsuInt

        self.ospf_intfs = []

        for i in range(2):
            intfs = OSPFInterface(ips[i], subnets[i], HELLO_INT, self.routerID, self.areaID)
            self.ospf_intfs.append(intfs)

        self.flood_timer = threading.Timer(3*lsuInt, self.floodLSU)
        self.flood_timer.start()
        self.adj_list = {routerID: []}
        self.link_states = {routerID: [(str(ip_network(s).network_address), str(ip_network(s).netmask)) for s in subnets]}
        self.routes = {}
        self.seq_num = {}

        self.sendHelloPkts()

    def dijkstra(self, subnet, mask):
        priority_queue = [(0, self.routerID, [self.routerID])]
        visited = set()

        while priority_queue:
            current_distance, current_node, path = heapq.heappop(priority_queue)

            if current_node not in visited:
                visited.add(current_node)

                if (subnet, mask) in self.link_states[current_node]:
                    return path

                for neighbor in self.adj_list[current_node]:
                    if neighbor not in visited:
                        heapq.heappush(priority_queue, (current_distance + 1, neighbor, path + [neighbor]))

        return None

    def getSrcInfo(self, ip):
        for idx, subnet in enumerate(self.subnets):
            if ip_address(ip) in ip_network(subnet):
                return self.ips[idx], self.macs[idx], subnet
        return None, None, None

    def getIPFromID(self, rid):
        for intf in self.ospf_intfs:
            for neighbourIP, neighbourID in intf.neighbours:
                if rid == neighbourID:
                    return neighbourIP

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        print("New MAC addr entry {} --> {}".format(mac, port))

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def addArpEntry(self, ip, mac):
        if self.arp_cache.lookup(ip):
            return

        if any(ip_address(ip) in ip_network(subnet) for subnet in self.subnets):
            self.arp_cache.add_entry(ip, mac)

    def handleArpReply(self, pkt):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpEntry(src_ip, pkt[ARP].hwsrc)

        if dst_ip in self.ips and dst_ip in self.pkt_cache:
            cached = self.pkt_cache[dst_ip]
            cached[Ether].dst = pkt[Ether].dst
            self.send(cached)
            del self.pkt_cache[dst_ip]

        self.send(pkt)

    def handleArpRequest(self, pkt):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        if src_ip in self.ips:
            return

        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpEntry(src_ip, pkt[ARP].hwsrc)

        _, mac, subnet = self.getSrcInfo(dst_ip)

        if subnet and dst_ip in self.ips:
            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = mac
            pkt[ARP].psrc = dst_ip
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = mac
            self.send(pkt)

    def sendArpRequest(self, pkt, ip):
        src_ip, src_mac,_ = self.getSrcInfo(ip)

        if src_mac is None or src_ip is None:
            return

        src_port = pkt[CPUMetadata].srcPort
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / CPUMetadata(srcPort=src_port) / ARP(
            hwsrc=src_mac, psrc=src_ip, pdst=ip, hwdst="00:00:00:00:00:00",
            op=ARP_OP_REQ, hwlen=6, plen=4, hwtype=1, ptype=0x800)

        self.pkt_cache[src_ip] = pkt
        self.send(arp_req)

    def sendHelloPkts(self):
        for idx, intf in enumerate(self.ospf_intfs):
            src_mac = self.macs[idx]
            pkt = intf.build_hello_packet(src_mac)
            self.send(pkt)

        threading.Timer(HELLO_INT, self.sendHelloPkts).start()

    def floodLSU(self):
        self.floodLSUPkts()
        self.flood_timer = threading.Timer(3*self.lsuInt,self.floodLSU)
        self.flood_timer.start()

    def floodLSUPkts(self):
        lsu_adverts = []

        for routerID in self.link_states:
            for entry in self.link_states[routerID]:
                lsu_adverts.append((entry, routerID))

        lsu_packets = [LSU(subnet=subnet, mask=mask, routerID=rid) for (subnet, mask), rid in lsu_adverts]
        num_adverts = len(lsu_packets)

        for neighborID in self.adj_list[self.routerID]:
            dst_ip = self.getIPFromID(neighborID)
            src_ip = self.getSrcIp(dst_ip)

            l2 = Ether(dst="ff:ff:ff:ff:ff:ff")
            l2_metadata = CPUMetadata(origEtherType=0x0800, srcPort=1)
            l3 = IP(src=src_ip, dst=dst_ip, proto=89)
            pwospf_lsu = PWOSPF(type=LSU_TYPE, routerID=self.routerID, areaID=self.areaID,
                                seqNum=self.sequence, ttl=TTL_DEFAULT, num_adverts=num_adverts,
                                adverts=lsu_packets)

            lsu_packet = l2 / l2_metadata / l3 / pwospf_lsu

            if not self.arp_cache.lookup(dst_ip):
                self.sendArpRequest(lsu_packet, dst_ip)
            else:
                self.send(lsu_packet)

        self.sequence += 1

    def getSrcIp(self, dst_ip):
        for i, subnet in enumerate(self.subnets):
            if ip_address(dst_ip) in ip_network(subnet):
                return self.ips[i]
        return None

    def getIPFromID(self, rid):
        for intf in self.ospf_intfs:
            for neighbourIP, neighbourID in intf.neighbours:
                if rid == neighbourID:
                    return neighbourIP

    def handlePWOSPFLSU(self, pkt):
        routerID = pkt[PWOSPF].routerID
        routerIP = pkt[IP].src

        known = False
        update = False

        for intf in self.ospf_intfs:
            if (routerIP, routerID) in intf.neighbours:
                known = True

        if not known:
            return

        current_ad = pkt[PWOSPF].adverts[0]
        num_adverts = pkt[PWOSPF].num_adverts

        for _ in range(num_adverts):
            rid = current_ad.routerID

            if rid not in self.link_states:

                if rid != self.routerID:
                    if rid not in self.adj_list[routerID]:
                        self.adj_list[routerID].append(rid)

                    if rid not in self.adj_list:
                        self.adj_list[rid] = []

                    self.adj_list[rid].append(routerID)

                self.link_states[rid] = []

            subnet, mask = current_ad.subnet, current_ad.mask

            if (subnet, mask) not in self.link_states[rid]:
                self.link_states[rid].append((subnet, mask))
                update = True

            path = self.dijkstra(subnet, mask)

            if len(path) > 1:

                next_hop = self.getIPFromID(path[1])

                if (subnet, mask) in self.routes:

                    self.sw.removeTableEntry(
                        table_name='MyIngress.routing_table',
                        match_fields={'hdr.ipv4.dstAddr': [subnet, mask]},
                        action_name='MyIngress.set_next_hop',
                        action_params={'next_hop': self.routes[(subnet, mask)]},
                        priority= 1 if mask == MASK_2  else 2
                    )

                self.routes[(subnet, mask)] = next_hop

                self.sw.insertTableEntry(
                    table_name='MyIngress.routing_table',
                    match_fields={'hdr.ipv4.dstAddr': [subnet,  mask]},
                    action_name='MyIngress.set_next_hop',
                    action_params={'next_hop': self.routes[(subnet, mask)]},
                    priority= 1 if mask == MASK_2  else 2
                )

            current_ad = current_ad.payload

        if update:
            self.flood_timer.cancel()
            self.flood_timer = threading.Timer(3*self.lsuInt,self.floodLSU)
            self.flood_timer.start()
            self.floodLSUPkts()


    def handlePWOSPFHello(self, pkt):
        src_ip = pkt[IP].src
        ospf = pkt[PWOSPF]
        routerID = ospf.routerID
        subnet = str(ip_network(int(ip_address(src_ip)) & MASK).network_address)

        # Ignore Hello packets not from the same area
        if ospf.areaID != self.areaID:
            return

        for intf in self.ospf_intfs:
            if ip_address(src_ip) in ip_network(intf.subnet):

                self.addMacAddr(pkt[Ether].src, pkt[CPUMetadata].srcPort)
                self.addArpEntry(src_ip, pkt[Ether].src)

                intf.update_timer(routerID, src_ip)

                if intf.is_lsu_needed():
                    self.link_states[routerID] = []

                    if routerID not in self.adj_list:
                        self.adj_list[routerID] = []

                    if self.routerID not in self.adj_list[routerID]:
                        self.adj_list[routerID].append(self.routerID)

                    if routerID not in self.adj_list[self.routerID]:
                        self.adj_list[self.routerID].append(routerID)

                    if (src_ip, MASK) not in self.routes:

                        self.routes[(src_ip, MASK)] = src_ip

                    self.sw.insertTableEntry(
                        table_name='MyIngress.routing_table',
                        match_fields={'hdr.ipv4.dstAddr': [subnet, MASK]},
                        action_name='MyIngress.set_next_hop',
                        action_params={'next_hop': src_ip},
                        priority=2
                    )

                    self.flood_timer.cancel()
                    self.flood_timer = threading.Timer(3*self.lsuInt,self.floodLSU)
                    self.flood_timer.start()
                    self.floodLSUPkts()


    def handleIP(self, pkt):
        dst_ip = pkt[IP].dst
        self.sendArpRequest(pkt, dst_ip)

    def handlePkt(self, pkt):
        if CPUMetadata not in pkt or pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

        if PWOSPF in pkt:
            if pkt[PWOSPF].type == HELLO_TYPE:
                self.handlePWOSPFHello(pkt)
            elif pkt[PWOSPF].type == LSU_TYPE:
                self.handlePWOSPFLSU(pkt)

        elif IP in pkt:
            self.handleIP(pkt)

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
        super(Controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Controller, self).join(*args, **kwargs)