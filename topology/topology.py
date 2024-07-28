
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch


class MyTopo(Topo):
    def __init__(self):

        # Initialize topology
        Topo.__init__(self)

        # Here you initialize hosts, web servers and switches
        # (There are sample host, switch and link initialization,  you can rewrite it in a way you prefer)

        # PROJECT TOPOLOGY:
        #    H1 ----- SW1 ----- H2
        #              |
        #             FW1
        #              |                          |---- WS1
        #             SW2 --- ids --- lb1 --- SW4 |---- WS2
        #              |       |                  |---- WS3
        #              |    inspector
        #             FW2
        #              |  
        #             nat
        #              |
        #    H3 ----- SW3 ----- H4

        # Initialize hosts (https://mininet.org/api/classmininet_1_1net_1_1Mininet.html#af4136b2706380e1624d31449b657d936)
        print( '*** Adding hosts\n' )
        h1 = self.addHost('h1', ip='100.0.0.10/24')
        h2 = self.addHost('h2', ip='100.0.0.11/24')
        h3 = self.addHost('h3', ip='100.0.0.50/24')
        h4 = self.addHost('h4', ip='100.0.0.51/24')
        insp = self.addHost('insp', ip='100.0.0.30/24')

        
        # Initialize webservers
        print( '*** Adding web servers\n' )
        ws1 = self.addHost('ws1', ip='100.0.0.40/24')
        ws2 = self.addHost('ws2', ip='100.0.0.41/24')
        ws3 = self.addHost('ws3', ip='100.0.0.42/24')

        # Initial switches (https://mininet.org/api/classmininet_1_1net_1_1Mininet.html#a449aeb6f2b9fb66b7aedacfc2105642a)
        print( '*** Adding switches\n' )
        sw1 = self.addSwitch('sw1', dpid="1")
        sw2 = self.addSwitch('sw2', dpid="2")
        sw3 = self.addSwitch('sw3', dpid="3")
        sw4 = self.addSwitch('sw4', dpid="4")

        # Click modules
        print( '*** Adding click modules\n' )
        ids = self.addSwitch('ids', dpid="9")
        
        # Initial firewalls --> TODO: Mirar bien lo de la instance de la class FW
        print( '*** Adding firewalls\n' )
        fw1 = self.addSwitch('fw1', dpid="5")
        fw2 = self.addSwitch('fw2', dpid="6")

        print( '*** Adding middleboxes\n')
        napt = self.addSwitch('napt', dpid="8")
        
        # NFV - TODO: Review DPID number
        print( '*** Adding NFV\n' )
        lb1 = self.addSwitch('lb1', dpid="7")
        
        # Defining links (https://mininet.org/api/classmininet_1_1link_1_1Link.html#a41a0b07779d7f445d9d21948c3086f5b)
        # Public zone links
        print( '*** Creating Public Zone links\n' )
        self.addLink(h1, sw1)
        self.addLink(h2, sw1)
        self.addLink(sw1, fw1, port2=1)
        

        # DmZ links
        print( '*** Creating DmZ links\n' )
        self.addLink(sw2, ids, port1=3, port2=1)
        self.addLink(ids, lb1, port1=2,port2=1)
        self.addLink(ids, insp, port1=3, port2=1)

        # DmZ links - TODO: Modify the connectios to include IDS
        print( '*** Creating DmZ links\n' )        
        self.addLink(ws1, sw4, port1=1, port2=1)
        self.addLink(ws2, sw4, port1=1, port2=2)
        self.addLink(ws3, sw4, port1=1, port2=3)
        self.addLink(sw2, fw1, port1=1, port2=2)
        self.addLink(sw2, fw2, port1=2, port2=1)
        self.addLink(lb1, sw4, port1=2, port2=4)

        
        # Private zone links
        print( '*** Creating Private Zone links\n' )
        #self.addLink(fw2, sw3, port1=2)
        self.addLink(sw3, napt, port2=2)
        self.addLink(napt, fw2, port1=1, port2=2)
        self.addLink(h3, sw3)
        self.addLink(h4, sw3)

def startup_services(net):
    # Start http services and executing commands you require on each host...
    server = net.get("ws1")
    server.cmd("python3 -m http.server 80 &")
    server = net.get("ws2")
    server.cmd("python3 -m http.server 80 &")
    server = net.get("ws3")
    server.cmd("python3 -m http.server 80 &")

    # Start INSP
    inspServer = net.get("insp")
    inspServer.cmd("tcpdump -i insp-eth0 -w insp.pcap &")


    
    return

topos = {'mytopo': (lambda: MyTopo())}

if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)


    startup_services(net)
    # Start the network

    # Needed to set the default gateway for the private hosts
    net.get("h3").cmd("ip route add default via 10.0.0.1")
    net.get("h4").cmd("ip route add default via 10.0.0.1")

    net.start()

    # Start the CLI
    CLI(net)
    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###
    
    net.stop()
