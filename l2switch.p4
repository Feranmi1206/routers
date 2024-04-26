from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from ipaddress  import ip_network, ip_address, IPv4Address
from pwospf import PWOSPF, LSU
import time, threading
import heapq

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
MASK = 0xFFFFFFFF
HELLO_INT = 0x5
HELLO_TYPE = 0x1
LSU_TYPE = 0x4
TTL_DEFAULT = 0x1e

ALLSPFRouters = "224.0.0.5"

class Routes():
    def __init__(self,sw,routerID,areadID,subnet_masks,intfs_ips, intfs_ospf):
        self.sw = sw
        self.routerID = routerID
        self.areadID = areadID

        self.ospf_intfs = intfs_ospf
        self.ips = intfs_ips #Your own interface IPs
        self.id_to_ip = {} #Tracks the interface for the RID.
        self.subnet_masks = subnet_masks #These are the subnets that I own
        self.adj = {routerID: []} #Maps RID --> list of RID. updated on Hello Packet
        self.lsa = {routerID: self.subnet_masks} #Maps RID --> (subnet,mask) updated on LSU. If the subnet is on your own put a mask of /32
        self.routes = {} #Maps Subnet+Mask --> Next Hop IP. Keep track of state of Dataplane table
        self.seq_num = {} #Maps Adjacent Host(RID) --> Sequence number of LSU


    def check_seq(self,pkt):
        rid = pkt[PWOSPF].routerID
        if rid not in self.seq_num.keys():
            self.seq_num[rid] = pkt[PWOSPF].seqNum
            return False
        if pkt[PWOSPF].seqNum <= self.seq_num[rid]:
            return True
        self.seq_num[rid] = pkt[PWOSPF].seqNum
        return False

    #TODO: if change is detected in LSU, send LSU flood?
    def update_lsu(self,pkt):
        rid = pkt[PWOSPF].routerID
        rip = pkt[IP].src
        if self.check_seq(pkt):
            return
        #Check Link Status for this neighbor, has to be one of the interfaces
        valid = False
        change = False
        #Has to be a trusted interface
        for i in self.ospf_intfs:
            if rid in i.neighbor_ids and rip in i.neighbor_ips:
                valid = True
                break
        if valid:
            lsu_ads = pkt[PWOSPF].advertisements
            lsu_ad = pkt[PWOSPF].advertisements[0]
            lsu_num = pkt[PWOSPF].adverts
            print(f"{self.sw} --> PRIOR: {self.lsa}")
            for i in range(0,lsu_num):
                lsu_rid = lsu_ad.routerID
                if lsu_rid not in self.lsa:
                    #Also add to Adjacency graph of neighbor
                    if lsu_rid not in self.adj[pkt[PWOSPF].routerID]:
                        self.adj[pkt[PWOSPF].routerID].append(lsu_rid)
                        if lsu_rid not in self.adj:
                            self.adj[lsu_rid] = []
                        self.adj[lsu_rid].append(pkt[PWOSPF].routerID)
                        print(f"{self.sw} --> EDGE {self.adj}")
                    self.lsa[lsu_rid] = []
                subnet = lsu_ad.subnet
                mask = lsu_ad.mask
                if (subnet,mask) not in self.lsa[lsu_rid]:
                    print(f"{self.sw} --> ADDING {subnet}/{mask}/{lsu_rid}")
                    self.lsa[lsu_ad.routerID].append((subnet,mask))
                    change = True
                path = self.next_hop(subnet,mask)
                #print(f"{self.sw} --> {path} to {subnet}/{mask}")
                if len(path) > 1:
                    next_hop =self.id_to_ip[path[1]]
                    mask = 0xFFFFFF00
                    key = (subnet,mask)
                    if key in self.routes:
                        self.edit_route(next_hop,subnet,mask)
                    else:
                        self.add_route(next_hop,subnet,mask)
                    self.routes[key] = next_hop
                lsu_ad = lsu_ad.payload
        #Debug Prints
        if change:
            print(f"{self.sw}:ADJ {self.adj}\n")
            print(f"{self.sw}:LSA {self.lsa}\n")
            print(f"{self.sw}:ROUTES {self.routes}\n")
        return change

    #Add as neighboring node
    def add_adj(self,rid):
        if rid not in self.adj.keys():
            self.adj[rid] = []
        if rid not in self.adj[self.routerID]:
            self.adj[self.routerID].append(rid)
        if self.routerID not in self.adj[rid]:
            self.adj[rid].append(self.routerID)
    def del_adj(self,rid):
        for i in self.adj[rid]:
            if i in self.adj.keys():
                self.adj[i].remove(rid)
        del self.adj[rid]

    def edit_route(self,ip,subnet,mask):
        self.del_route(ip,subnet,mask)
        self.add_route(ip,subnet,mask)

    def add_route(self,ip,subnet,mask):
        priority = 1 if mask == 0xFFFFFF00 else 2
        #print(f"{self.sw}: {subnet},{mask} --> {ip}")
        self.sw.insertTableEntry(
            table_name="MyIngress.routing_table",
            match_fields={"hdr.ipv4.dstAddr": [subnet,mask]},
            action_name="MyIngress.set_next_hop",
            action_params={"next_hop":ip},
            priority = priority,
        )
    def del_route(self,ip,subnet,mask):
        priority = 1 if mask == 0xFFFFFF00 else 2
        #print(f"del {self.sw}: {subnet},{mask} --> {ip}")
        self.sw.removeTableEntry(
            table_name="MyIngress.routing_table",
            match_fields={"hdr.ipv4.dstAddr": [subnet,mask]},
            action_name="MyIngress.set_next_hop",
            action_params={"next_hop":ip},
            priority = priority,
        )

    def find_node(self,rid,ip):
        self.id_to_ip[rid] = ip
        self.add_adj(rid)
        self.lsa[rid] = []
        mask = 0xFFFFFFFF
        if (ip,mask) not in self.routes.keys():
            self.routes[(ip,mask)] = ip
            subnet = str(ip_network(int(ip_address(ip)) & mask).network_address)
            self.add_route(ip,subnet,mask)

    def next_hop(self,subnet,mask):
        visited = set()
        queue = [(self.routerID, [self.routerID])]

        while queue:
            current, path = queue.pop(0)

            if current not in visited:
                visited.add(current)

                if (subnet, mask) in self.lsa[current]:
                    return path

                for neighbor in self.adj[current]:
                    if neighbor not in visited:
                        queue.append((neighbor, path + [neighbor]))



class ArpCache:
    def __init__(self, sw, timeout=120):
        self.sw = sw
        self.arp_entries = {}
        self.timers = {}
        self.timeout = timeout

    def in_cache(self, ip):
        return (ip in self.arp_entries.keys())

    def add_entry(self, ip, mac):
        print("Adding new ARP entry {} --> {}".format(ip, mac))
        self.arp_entries[ip] = mac

        timer = threading.Timer(self.timeout, self.remove_entry, args=[ip, mac])
        self.timers[ip] = timer
        timer.start()
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip_addr': [ip, MASK]},
                action_name='MyIngress.arp_match',
                action_params={'dst_mac_addr': mac},
                priority = 1)

    def remove_entry(self, ip, mac):
        print("Removing expired ARP entry {} --> {}".format(ip, mac))


        self.sw.removeTableEntry(table_name='MyIngress.arp_table',
            match_fields={'next_hop_ip_addr': [ip, MASK]},
            action_name='MyIngress.arp_match',
            action_params={'dst_mac_addr': mac},
            priority = 1)

        del self.arp_entries[ip]

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
        self.neighbor_ids = []
        self.neighbor_ips = []

    def update_timer(self, neighbor_id, neighbor_ip):
        timer_info = self.timers.get(neighbor_ip)
        if timer_info:
            timer, _ = timer_info
            timer.cancel()
        else:
            self.neighbor_ips.append(neighbor_ip)
            self.neighbor_ids.append(neighbor_id)
            self.flag = True

        timer = threading.Timer(3 * self.helloInt, self.handle_timer_expiration, args=[neighbor_ip, neighbor_id])
        self.timers[neighbor_ip] = (timer, neighbor_id)
        timer.start()

    def handle_timer_expiration(self, neighbor_ip, neighbor_id):
        print(f"Timeout on {neighbor_ip}")
        self.neighbor_ips.remove(neighbor_ip)
        self.neighbor_ids.remove(neighbor_id)
        del self.timers[neighbor_ip]
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
        self.host_seq = 0

        self.arp_cache = ArpCache(sw)
        self.pkt_cache = {}
        subnet_masks = []
        for s in subnets:
            net = ip_network(s)
            subnet_masks.append((str(net.network_address),str(net.netmask)))

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
            self.ospfHelloCallback(HELLO_INT, intfs, i)

        self.lsu_timer = threading.Timer(3*lsuInt, self.pwospf_lsu_flood_wrapper)
        self.lsu_timer.start()
        self.routes = Routes(sw, routerID, areaID, subnet_masks, ips, self.ospf_intfs)

    def addMacAddr(self, mac, port):
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
                    print("Arp reply failure")
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

        subnet = None
        for idx, s in enumerate(self.subnets):
            if ip_address(dst_ip) in ip_network(s):
                subnet = s
                break

        if subnet and dst_ip in self.ips:
            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = self.macs[idx]
            pkt[ARP].psrc = dst_ip
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.macs[idx]
            self.send(pkt)

    def sendArpRequest(self, pkt, ip):
        src_ip = None
        src_mac = None
        for idx, s in enumerate(self.subnets):
            if ip_address(ip) in ip_network(s):
                src_mac = self.macs[idx]
                src_ip = self.ips[idx]
                break

        if src_mac is None or src_ip is None:
            return

        src_port = pkt[CPUMetadata].srcPort
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / CPUMetadata(srcPort=src_port) / ARP(
            hwsrc=src_mac, psrc=src_ip, pdst=ip, hwdst="00:00:00:00:00:00",
            op=ARP_OP_REQ, hwlen=6, plen=4, hwtype=1, ptype=0x800)

        self.pkt_cache[ip] = pkt
        self.send(arp_req)

    def ospfHelloCallback(self, interval, interface, idx):
        threading.Timer(interval,self.ospfHelloCallback,args =[interval, interface, idx]).start()
        src_mac = self.macs[idx]
        pkt = interface.build_hello_packet(src_mac)
        self.send(pkt)

    def pwospf_lsu_flood_wrapper(self):
        self.floodLSUPkt()
        self.lsu_timer = threading.Timer(3*self.lsuInt,self.pwospf_lsu_flood_wrapper)
        self.lsu_timer.start()

    def floodLSUPkt(self):
        neighbor_routers = self.routes.adj[self.routerID]
        lsu_ads = []
        for rid in self.routes.lsa:
            for v in self.routes.lsa[rid]:
                lsu_ads.append((v,rid))
        print(f"{self.sw}: LSU_AD_SEND --> {lsu_ads}")
        lsu_ads_pkt = [LSU(subnet = s, mask = m, routerID = r) for (s,m),r in lsu_ads]
        for n in neighbor_routers:
            dst_ip = self.routes.id_to_ip[n]
            src_ip = self.getSrcIp(dst_ip)
            l2 = Ether(dst ="ff:ff:ff:ff:ff:ff")
            l2_cpumetadata = CPUMetadata(origEtherType=0x0800, srcPort = 1)
            l3 = IP(src = src_ip,dst = dst_ip,proto=89)
            l3_pwospf_flood = PWOSPF(type=LSU_TYPE,routerID = self.routerID, areaID = self.areaID, seqNum = self.host_seq, ttl = TTL_DEFAULT,adverts = len(lsu_ads_pkt), advertisements = lsu_ads_pkt)
            lsu_pkt = l2 / l2_cpumetadata / l3 / l3_pwospf_flood
            if not self.arp_cache.in_cache(dst_ip):
                self.sendArpRequest(lsu_pkt,dst_ip)
            else:
                self.send(lsu_pkt)
        self.host_seq += 1

    def getSrcIp(self, dst_ip):
        for i, subnet in enumerate(self.subnets):
            if ip_address(dst_ip) in ip_network(subnet):
                return self.ips[i]
        return None

    def handlePWOSPFLSU(self, pkt):
        if self.routes.update_lsu(pkt):
            self.lsu_timer.cancel()
            self.lsu_timer = threading.Timer(3*self.lsuInt,self.pwospf_lsu_flood_wrapper)
            self.lsu_timer.start()
            self.floodLSUPkt()

    def handlePWOSPFHello(self, pkt):
        incoming_ip = pkt[IP].src
        routerID = pkt[PWOSPF].routerID
        for intfs in self.ospf_intfs:
            if ip_address(incoming_ip) in ip_network(intfs.subnet):
                intfs.update_timer(routerID, incoming_ip)
            if intfs.is_lsu_needed():
                self.routes.find_node(routerID, incoming_ip)
                self.lsu_timer.cancel()
                self.lsu_timer = threading.Timer(3*self.lsuInt,self.pwospf_lsu_flood_wrapper)
                self.lsu_timer.start()
                self.floodLSUPkt()

    def handlePWOSPF(self, pkt):
        if pkt[PWOSPF].type == HELLO_TYPE:
            self.handlePWOSPFHello(pkt)
        elif pkt[PWOSPF].type == LSU_TYPE:
            self.handlePWOSPFLSU(pkt)

    def handleIP(self, pkt):
        dst_ip = pkt[IP].dst
        self.sendArpRequest(pkt, dst_ip)

    def handlePkt(self, pkt):
        if CPUMetadata not in pkt:
            return
        if pkt[CPUMetadata].fromCpu == 1: return
        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        if PWOSPF in pkt:
            self.handlePWOSPF(pkt)
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