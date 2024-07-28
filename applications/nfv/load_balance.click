

//		 -----  eth1   -----  eth2   -----       |--- WS1 (10.0.0.40)
//		| IDS | ----- | LB1 | ----- | SW4 | ---- |--- WS2 (10.0.0.41)
//		 -----  PORT1  -----  PORT2  -----       |--- WS3 (10.0.0.42)
//				  (10.0.0.45 : 80)

//------------------------------------------------------Global variables-----------------------------------------------------------
define($PORT1 lb1-eth1, $PORT2 lb1-eth2);
Script(print "Click LoadBalancer on $PORT1 $PORT2");

WSChoice :: RoundRobinIPMapper(
    100.0.0.45 - 100.0.0.40 - 0 1,
    100.0.0.45 - 100.0.0.41 - 0 1,
    100.0.0.45 - 100.0.0.42 - 0 1);
IPRewrite :: IPRewriter (WSChoice);

inRequest :: ARPQuerier(100.0.0.45, 10:10:A0:A0:07:07);
inResponse :: ARPResponder(100.0.0.45 10:10:A0:A0:07:07);

outRequest :: ARPQuerier(100.0.0.45, 20:20:B0:B0:07:07);
outResponse :: ARPResponder(100.0.0.45 20:20:B0:B0:07:07);

discardPckt :: Counter;
countDiscard :: Queue -> discardPckt -> Discard;

elementclass prepareIPPacket{
         input
        ->Strip(14)
        ->CheckIPHeader
        ->output
}
//---------------------------------------------------------------------------------------------------------------------------------

//----------------------------------------------Global variables to web servers----------------------------------------------------
inPckt :: AverageCounter;
arpRequestIn, arpReplyIn, ipIn, icmpIn :: Counter;

from_outside :: FromDevice($PORT1, SNIFFER false, METHOD LINUX);
webServer :: ToDevice($PORT2, METHOD LINUX);
to_inside :: Queue -> webServer;
to_inside_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]outRequest -> to_inside;
IPRewrite[0] -> to_inside_queue;
//---------------------------------------------------------------------------------------------------------------------------------

//------------------------------------------------Global variables to clients------------------------------------------------------
outPckt :: AverageCounter;
arpRequestOut, arpReplyOut, ipOut, icmpOut :: Counter;

from_inside :: FromDevice($PORT2, SNIFFER false, METHOD LINUX);
client :: ToDevice($PORT1, METHOD LINUX);
to_outside :: Queue -> client;
to_outside_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]inRequest -> to_outside;
IPRewrite[1] -> to_outside_queue;
//---------------------------------------------------------------------------------------------------------------------------------

//---------------------------------------Pipeline to web servers (from_outside -> to_inside)---------------------------------------
inPacketClassifier :: Classifier(
	12/0800,              // IP packet
	12/0806 20/0001,      // ARP request packet 
	12/0806 20/0002,      // ARP reply packet 
	-                     // Other
)

incomingIPPacketClassifier :: IPClassifier(
	tcp dst port 80,	  // TCP connection to servers
	icmp,				  // ICMP to servers
	-					  // Others (ex.: UDP)
)


from_outside -> inPckt -> inPacketClassifier;

// 1. Classify incoming packets
//		[0] = IP
//		[1] = ARP request, create response and send back
//		[2] = ARP reply
//		[3] = Discard

inPacketClassifier[0] -> prepareIPPacket -> incomingIPPacketClassifier;
inPacketClassifier[1] -> arpRequestIn -> inResponse -> to_outside;
inPacketClassifier[2] -> arpReplyIn -> [1]inRequest;
inPacketClassifier[3] -> countDiscard -> Discard;

// 2. Classify IP packets
//		[0] = RoundRobin + IPRewriter
//		[1] = ICMP, create response and send back
//		[2] = Discard

incomingIPPacketClassifier[0] -> Unstrip(14) -> ipIn -> [0]IPRewrite;
incomingIPPacketClassifier[1] -> Unstrip(14) -> icmpIn -> ICMPPingResponder -> to_outside_queue;
incomingIPPacketClassifier[2] -> countDiscard -> Discard;
//---------------------------------------------------------------------------------------------------------------------------------

//-----------------------------------------Pipeline to clients (from_inside -> to_outside)-----------------------------------------
outPacketClassifier :: Classifier(
	12/0800,              // IP packet
	12/0806 20/0001,      // ARP request packet 
	12/0806 20/0002,      // ARP reply packet 
	-                     // Other
)

outgoingIPPacketClassifier :: IPClassifier(
	tcp && src port 80,	  // TCP connection from servers
	icmp type echo,		  // ICMP response from servers
	-					  // Others (ex.: UDP)
)

from_inside -> outPckt -> outPacketClassifier;

// 1. Classify outgoing packets
//		[0] = IP
//		[1] = ARP request
//		[2] = ARP reply
//		[3] = Discard

outPacketClassifier[0] -> prepareIPPacket -> outgoingIPPacketClassifier;
outPacketClassifier[1] -> arpRequestOut -> outResponse -> to_inside;
outPacketClassifier[2] -> arpReplyOut -> [1]outRequest;
outPacketClassifier[3] -> countDiscard -> Discard;

// 2. Classify IP packets
//		[0] = RoundRobin + IPRewriter
//		[1] = ICMP
//		[2] = Discard

outgoingIPPacketClassifier[0] -> ipOut -> [0]IPRewrite;
outgoingIPPacketClassifier[1] -> icmpOut -> ICMPPingResponder -> to_inside_queue;
outgoingIPPacketClassifier[2] -> countDiscard -> Discard;
//---------------------------------------------------------------------------------------------------------------------------------

//--------------------------------------------------------Final report-------------------------------------------------------------
DriverManager(
	pause
	// ,
	// print
	// "
		// =================== LB1 Report ===================
// 
		// Total # of input packets: $(inPckt.count)
		// Total # of output packets: $(outPckt.count)
// 
		// Total # of ARP requests: $(add $(arpRequestIn.count) $(arpRequestOut.count))
		// Total # of ARP responses: $(add $(arpReplyIn.count) $(arpReplyOut.count))
// 
		// Total # of service packets: $(add $(inIP.count) $(outIP.count))
		// Total # of ICMP packets: $(add $(icmpIn.count) $(icmpOut.count))
		// Total # of dropped packets: $(add $(discardPckt.count))
// 
		// =================================================
		// "
)
//---------------------------------------------------------------------------------------------------------------------------------