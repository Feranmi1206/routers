from mininet.topo import Topo


class SwitchTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")

        switches = [s1,s2,s3]

        for num, switch in enumerate(switches):

            subnet = "{0}{0}.{0}{0}.{0}{0}".format(num + 1)

            print("----------------------------------------------------------")
            print("SUBNET: " + subnet + ".0/24")
            print("----------------------------------------------------------")

            for i in range(1, 4):

                host_num = 3 * num + i
                host_ip = subnet + ".%d0" % i
                print("h%d: " % host_num + str(host_ip))
                print("Port: " + str(i))
                print("Mac Addr: " + "00:00:00:00:00:%02x" % host_num)
                host = self.addHost(
                    "h%d" % host_num, ip=host_ip, mac="00:00:00:00:00:%02x" % host_num
                )
                self.addLink(host , switch, port2 = i)
                print("\n")

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s1)
