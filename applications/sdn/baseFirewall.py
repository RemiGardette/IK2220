from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from forwarding import l2_learning
log = core.getLogger()


# This is the basic Firewall class which implements all features of your firewall!
# For upcoming packets, you should decide if the packet is allowed to pass according to the firewall rules (which you have provided in networkFirewalls file during initialization.)
# After processing packets you should install the correct OF rule on the device to threat similar packets the same way on dataplane (without forwarding packets to the controller) for a specific period of time.

# rules format:
# [input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, allow/block]
# Checkout networkFirewalls.py file for detailed structure.

class Firewall (l2_learning.LearningSwitch):

    rules = []
    name = "unnamed_firewall"
    connection = None

    def __init__(self, connection, name):

        # Initialization of your Firewall. You may want to keep track of the connection, device name and etc.

        self.name = name
        self.connection = connection
        super(Firewall, self).__init__(connection, False)
        
        ### COMPLETE THIS PART ###

    # Check if the incoming packet should pass the firewall.
    # It returns a boolean as if the packet is allowed to pass the firewall or not.
    # You should call this function during the _handle_packetIn event to make the right decision for the incoming packet.
    def has_access(self, ip_packet, input_port):
        ### COMPLETE THIS PART ###
        # Doc at https://noxrepo.github.io/pox-doc/html/#ip-version-4-ipv4

        print("********** packet incoming from port: ", input_port, " to ", self.name)

        source_port, dest_port, proto = "", "", ""
        if ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
            proto = 'ICMP'
            source_port = 'n/a'
            dest_port = 'n/a'
        elif ip_packet.protocol == ip_packet.TCP_PROTOCOL:
            proto = 'TCP'
            source_port = ip_packet.find('tcp').srcport
            dest_port = ip_packet.find('tcp').dstport
        elif ip_packet.protocol == ip_packet.UDP_PROTOCOL:
            proto = 'UDP'
            source_port = ip_packet.find('udp').srcport
            dest_port = ip_packet.find('udp').dstport
        else:
            proto = 'unknown'
            source_port = 'unknown'
            dest_port = 'unknown'                    
        print("Packet Characteristics:")
        print(f"Input Port: {input_port}")
        print(f"Protocol: {proto}")
        print(f"Source IP: {ip_packet.srcip}")
        print(f"Source Port: {source_port}")
        print(f"Destination IP: {ip_packet.dstip}")
        print(f"Destination Port: {dest_port}", "\n")
        
        print("Format: [input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, allow/block] \n")

        for rule in self.rules:

            input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, action = rule

            print("Rule: ", input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, action)

            # Check if the rule matches the packet
            if input_HW_port == input_port and self.check_protocol(ip_packet, protocol) and self.check_ip(ip_packet, src_ip, dst_ip) and self.check_ports(ip_packet, src_port, dst_port):
                print("Rule matched \n")
                return action == 'allow'
            else:
                print("input port: ", input_port, input_HW_port, "protocol: ", protocol, self.check_protocol(ip_packet, protocol), "ip: ", src_ip, dst_ip, self.check_ip(ip_packet, src_ip, dst_ip), "ports: ", src_port, dst_port, self.check_ports(ip_packet, src_port, dst_port))
                print("Rule did not match")
        # If no rule matched, return false
        print("No match for packet at ", self.name)
        return False

    # Subfunctions for the has_access function

    # Check if the protocol of the packet is the one expected (TCP, UDP or any)
    def check_protocol(self, ip_pkt, protocol):
        if protocol == 'any':
            return True
        elif protocol == 'TCP':
            return ip_pkt.protocol == ip_pkt.TCP_PROTOCOL
        elif protocol == 'UDP':
            return ip_pkt.protocol == ip_pkt.UDP_PROTOCOL
        else:
            return False

    # Check if the IPs are correct
    def check_ip(self, ip_pkt, src_ip, dst_ip):
        bool1, bool2 = True, True
        if src_ip != 'any':
            src = IPAddr(ip_pkt.srcip)
            bool1 = src.inNetwork(src_ip)
        if dst_ip != 'any':
            dst = IPAddr(ip_pkt.dstip)
            bool2 = dst.inNetwork(dst_ip)
        return bool1 and bool2
    
    # Check if the ports are correct
    def check_ports(self, ip_pkt, src_port, dst_port):
        bool1, bool2 = True, True
        unwrapped_pkt = ip_pkt.find('tcp')
        if unwrapped_pkt == None:
            unwrapped_pkt = ip_pkt.find('udp')
        if unwrapped_pkt == None and (src_port != 'any' or dst_port != 'any'):
            return False
        if src_port != 'any':
            print(unwrapped_pkt.srcport, src_port)
            bool1 = str(unwrapped_pkt.srcport) == src_port
        if dst_port != 'any':
            print(unwrapped_pkt.dstport, dst_port)
            bool2 = str(unwrapped_pkt.dstport) == dst_port
        return bool1 and bool2

    # On receiving a packet from dataplane, your firewall should process incoming event and apply the correct OF rule on the device.
    # doc at https://noxrepo.github.io/pox-doc/html/#how-do-i-create-a-firewall-block-tcp-ports

    def _handle_PacketIn(self, event):

        packet = event.parsed
        if not packet.parsed:
            print(self.name, ": Incomplete packet received! controller ignores that")
            return
        ofp_msg = event.ofp
        ### COMPLETE THIS PART ###

        # Update the firstSeenAt field in the controller
        mac_addr = packet.src
        dpid = event.connection.dpid   
        received_port = event.port 
        where = f"switch {dpid} - port {received_port}"    
        core.controller.updatefirstSeenAt(mac_addr, where)

        ip_pkt = packet.find('ipv4')
        if ip_pkt is None:
            super(Firewall, self)._handle_PacketIn(event)
            return

        # Handle no match packets, for now just drops them, this should not happend since we are supposed to have stateful rules
        has_access = self.has_access(ip_pkt, ofp_msg.in_port)

        # Handle packets that are allowed or blocked
        if has_access:
            print("Packet allowed at ", self.name)
            # If a packet is TCP or ICMP and allowed, we install a reverse rule to allow answers to reach the sender
            if ip_pkt.find('icmp') or ip_pkt.find('tcp'):
                print("Packet is TCP or ICMP, installing reverse rule")
                self.install_reverse_rule(packet, received_port)
            super(Firewall, self)._handle_PacketIn(event)
            return
        else:
            # Drop the packet
            print("Packet blocked at ", self.name)
            self.install_blocking_rule(packet, received_port)


            return

    # You are allowed to add more functions to this file as your need (e.g., a function for installing OF rules)

    # Install an OF rule to block a packet
    def install_blocking_rule(self, packet, input_port, idle_timeout = 10, hard_timeout = 30):
        match_obj = of.ofp_match.from_packet(packet, input_port)
        msg = of.ofp_flow_mod()
        msg.match = match_obj
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        self.connection.send(msg)

    # Install an OF rule to install a reverse rule
    def install_reverse_rule(self, packet, input_port, idle_timeout = 10, hard_timeout = 30):
        match_obj = of.ofp_match.from_packet(packet, input_port)
        reverse_match = of.ofp_match()
        reverse_match.dl_type = match_obj.dl_type
        reverse_match.dl_src = match_obj.dl_dst
        reverse_match.dl_dst = match_obj.dl_src
        reverse_match.nw_src = match_obj.nw_dst
        reverse_match.nw_dst = match_obj.nw_src
        if match_obj.nw_proto == pkt.ipv4.TCP_PROTOCOL:
            reverse_match.tp_src = match_obj.tp_dst
            reverse_match.tp_dst = match_obj.tp_src
        if input_port == 1:
            reverse_match.in_port = 2
        else:
            reverse_match.in_port = 1
        reverse_match.nw_proto = match_obj.nw_proto
        msg = of.ofp_flow_mod()
        msg.match = reverse_match
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        action = of.ofp_action_output(port=input_port)
        msg.actions.append(action)
        self.connection.send(msg)
        #print("reverse rule", reverse_match)
