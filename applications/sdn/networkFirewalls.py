from baseFirewall import Firewall


# Here we implement our network firewalls. All network firewalls are inherited from Firewall class.

# Rules parameters are:
# index 0: Determines the hardware port of the incoming packet.
# index 1: Determines the TCP layer protocol. (possible values: TCP, UDP, any)
# index 2: Determine the source IP address of the incoming packet. It should be either "any" or a subnet with "IP/Subnet" format (e.g, 100.0.0.40/32).
# index 3: Determine the TCP layer source port number of the incoming packet. (possible values: any, an integer as the port number)
# index 4: Determine the destination IP address of the incoming packet. Same format as the source IP.
# index 5: Determine the TCP layer destination port number of the incoming packet. Same format as the source port.
# index 6: To allow or block the matched packet. (possible values: allow, block)

# Note that the Firewall trace the rules from 0 to n and make the decision based on first matched rule.

# Hardware ports:
# public-zone --------- 1 FW1 2 ------------ DmZ
# DmZ ----------------- 1 FW2 2 ------------ private-zone

# Format: [index, protocol, source IP, source port, destination IP, destination port, action]

class FW1 (Firewall):

    def __init__(self, connection):

        """
        Initialize Firewall class and set rules!
        The following is just a sample to give you the idea.
        """

        ### COMPLETE THIS PART ###

        
        Firewall.__init__(self, connection, "FW1")
        self.rules = [
            [1, 'any', 'any', 'any', '100.0.0.45/32', 'any', 'allow'],
            [2, 'any', '100.0.0.45/32', 'any', 'any', 'any', 'allow'],
            # Allow all inbound traffic to the public zone from the private zone
            [2, 'any', '100.0.0.1/32', 'any', '100.0.0.10/31', 'any', 'allow'], 
            # Allow HTTP traffic on port 80 from the public zone to the DMZ LB
            # [2, 'TCP', '100.0.0.10/31', 'any', '100.0.0.45/32', '80', 'allow'],
            # # Block other TCP traffic from the public zone to the DMZ LB
            # [2, 'TCP', '100.0.0.10/31', 'any', '100.0.0.45/32', 'any', 'block'],
            # # Block UDP traffic from the public zone to the DMZ LB
            # [2, 'UDP', '100.0.0.10/31', 'any', '100.0.0.45/32', 'any', 'block'],
            # Allow ICMP traffic from the public zone to the DMZ LB

            # Block all other traffic from the public zone to the DMZ/private zone
            [1, 'any', '100.0.0.10/31', 'any', 'any', 'any', 'block'],
        ]


class FW2 (Firewall):
    def __init__(self, connection):

        """
        Initialize Firewall class and set rules!
        The following is just a sample to give you the idea.
        """

        ### COMPLETE THIS PART ###

        Firewall.__init__(self, connection, "FW2")
        self.rules = [
            # Allow all outbound traffic from the private-zone toward the public zone
            [2, 'any', '100.0.0.1/32', 'any', '100.0.0.10/31', 'any', 'allow'],
            # Block all inbound traffic from the public zone which is not a response to an outbound traffic
            [1, 'any', '100.0.0.10/31', 'any', 'any', 'any', 'block'],
            # Allow HTTP traffic on port 80 from the private zone to the DMZ LB
            [2, 'TCP', '100.0.0.1/32', 'any', '100.0.0.45/32', '80', 'allow'],
            # Block other TCP traffic from the private zone to the DMZ LB
            [2, 'TCP', '100.0.0.1/32', 'any', '100.0.0.45/32', 'any', 'block'],
            # Block UDP traffic from the private zone to the DMZ LB
            [2, 'UDP', '100.0.0.1/32', 'any', '100.0.0.45/32', 'any', 'block'],
            # Allow ICMP traffic from the private zone to the DMZ LB
            [2, 'any', '100.0.0.1/32', 'any', '100.0.0.45/32', 'any', 'allow'],
        ]