from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
import networkFirewalls
import webserver
import subprocess
import shlex
import datetime
import click_wrapper
# L2 Learning Controller: https://haryachyy.wordpress.com/2014/05/30/learning-pox-openflow-controller-l2-switch-implementation/
import l2_learning

log = core.getLogger()


class controller (object):
    # Here you should save a reference to each element:
    devices = dict()

    # Here you should save a reference to the place you saw the first time a specific source mac
    firstSeenAt = dict()
    
    # Connected devices
    index = 0

    def __init__(self):

        webserver.webserver(self)
        core.openflow.addListeners(self)
        
    def _handle_ConnectionUp(self, event):
        
        """
        This function is called everytime a new device starts in the network.
        You need to determine what is the new device and run the correct application based on that.
        
        Note that for normal switches you should use l2_learning module that already is available in pox as an external module.
        """
        
        id = event.dpid
        print(f"Device with DPID {id} connected")
        
        # FirewallS
        if id == 5:
            print("FW1 connected")
            # Add the FW1 reference from networkFirewalls to the devices dictonary
            self.devices[self.index] = networkFirewalls.FW1(event.connection)
            self.index += 1
            
        elif id == 6:
            print("FW2 connected")
            # Add the FW2 reference from networkFirewalls to the devices dictonary
            self.devices[self.index] = networkFirewalls.FW2(event.connection)
            self.index += 1

        # NAPT
        elif id == 8:
            print("NAPT connected")
            p = subprocess.Popen("sudo click /opt/pox/napt.click &", shell=True)
            log.info("Launched NAPT with PID:" +str(p.pid)+"\n")
            print("Started Click napt")
            
        # Load Balancer - TODO: Review ID number
        elif id == 7:
            print("Load Balancer connected")
            cmd = "sudo click /opt/pox/load_balance.click &"
            p = subprocess.Popen(cmd, shell = True)
            print("Started Click process for Load Balancer")
        
        elif id == 9:
            print("IDS connected")
            click_wrapper.start_click("/opt/pox/ids.click", "", "/tmp/ids.out", "/tmp/ids.err")

        # Switches
        else:
            print("SWITCH connected")
            # Intantiate a l2_learning and add it to the devices dictionary
            self.devices[self.index] = l2_learning.LearningSwitch(event.connection,False)
            self.index += 1
            
        return

    # This should be called by each element in your application when a new source MAC is seen

    def updatefirstSeenAt(self, mac, where):
       
        """
        This function updates your first seen dictionary with the given input.
        It should be called by each element in your application when a new source MAC is seen
        """
        
        # Check if the mac is already in the dictionary
        if mac in self.firstSeenAt:
            return      
        # If the MAC is not in the dictonary, add it
        else:
            time = datetime.datetime.now().isoformat()
            # self.firstSeenAt[mac] = (where, datetime.datetime.now().isoformat())
            self.firstSeenAt[mac] = (where, time)
            print(f"MAC {mac} added to dictionary at {time}")
        return

    def flush(self):

        """
        This will be called by the webserver and act as a 'soft restart'. It should:
        1) ask the switches to flush the rules (look for 'how to delete openflow rules'
        2) clear the mac learning table in each l2_learning switch (Python side) 
        3) clear the firstSeenAt dictionary: it's like starting from an empty state
        """
        
        # Flush the switches rules (Reference: poxwiki.pdf - Page 33, Example: Clearing tables on all switches)
        # Create ofp_flow_mod message to delete all flows (flow_mod match all flows by default)
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        # iterate over all connected switches and delete all their flows 
        for connection in core.openflow.connections:
            connection.send(msg)
            log.debug("Clearing all flows from %s." % (dpidToStr(connection.dpid),)) # type: ignore
        
        # Clear the MAC learning table of every L2Learning switch
        for key,value in self.devices.items():
            value.mactoPort = {}
            
        # Clear the firstSeenAt dictonary
        self.firstSeenAt.clear()
        
        return


def launch(configuration=""):
    core.registerNew(controller)
