import sys
sys.path.append("/home/feranmi/p4app/docker/scripts")

from p4app import P4Mininet

from controller import Controller
from my_topo import SwitchTopo
from mininet.cli import CLI

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SwitchTopo()
net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)

# Retrieve switch and host objects
h2, h3 = net.get('h2'), net.get('h3')
h5, h6 = net.get('h5'), net.get('h6')
h8, h9 = net.get('h8'), net.get('h9')

s1, s2, s3 = net.get("s1"), net.get("s2"), net.get("s3")

# Setup default routes for the hosts to enable connectivity
h2.cmd("route add default gw 11.11.11.1")
h2.cmd("route add default gw 11.11.11.1")
h3.cmd("route add default gw 11.11.11.1")

h5.cmd("route add default gw 22.22.22.1")
h6.cmd("route add default gw 22.22.22.1")

h8.cmd("route add default gw 33.33.33.1")
h9.cmd("route add default gw 33.33.33.1")
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
switches = ["s1","s2","s3"]

for switch in switches:
    sw = net.get(switch)
    sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 3))

    # Send MAC bcast packets to the bcast multicast group
    sw.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )

cpu1_routerID = "0.0.0.1"
cpu2_routerID = "0.0.0.2"
cpu3_routerID = "0.0.0.3"

# Start the MAC learning controller
cpu1 = Controller(s1, ["11.11.11.1", "44.44.44.1"], ["00:00:00:00:00:10","00:00:00:00:00:11"], ["11.11.11.0/24", "44.44.44.0/24"], cpu1_routerID)
cpu2 = Controller(s2, ["22.22.22.1", "44.44.44.2"], ["00:00:00:00:00:20","00:00:00:00:00:21"], ["22.22.22.0/24", "44.44.44.0/24"], cpu2_routerID)
cpu3 = Controller(s3, ["33.33.33.1", "44.44.44.3"], ["00:00:00:00:00:30","00:00:00:00:00:31"], ["33.33.33.0/24", "44.44.44.0/24"], cpu3_routerID)

mask = 0xFFFFFFFF

cpu1.routes.routes[("11.11.11.20", mask)] = "11.11.11.20"
cpu1.routes.routes[("11.11.11.30", mask)] = "11.11.11.30"

cpu2.routes.routes[("22.22.22.20", mask)] = "22.22.22.20"
cpu2.routes.routes[("22.22.22.30", mask)] = "22.22.22.30"

cpu3.routes.routes[("33.33.33.20", mask)] = "33.33.33.20"
cpu3.routes.routes[("33.33.33.30", mask)] = "33.33.33.30"

s1.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["11.11.11.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"11.11.11.20"},
    priority = 1,
)

s1.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["11.11.11.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"11.11.11.30"},
    priority = 1,
)

s2.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["22.22.22.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"22.22.22.20"},
    priority = 1,
)

s2.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["22.22.22.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"22.22.22.30"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["33.33.33.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"33.33.33.20"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["33.33.33.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"33.33.33.30"},
    priority = 1,
)

cpu1.start()
cpu2.start()
cpu3.start()
CLI(net)
net.stop()