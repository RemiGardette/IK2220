define($Sw2Port ids-eth1, $LbsPort ids-eth2, $InspPort ids-eth3);

//From Devices
FromSw2 :: FromDevice($Sw2Port, SNIFFER false, METHOD LINUX, PROMISC true);
FromLbs :: FromDevice($LbsPort, SNIFFER false, METHOD LINUX, PROMISC true);
//To Devices
ToSw2 :: Queue -> ToDevice($Sw2Port,METHOD LINUX);
ToLbs :: Queue -> ToDevice($LbsPort,METHOD LINUX);
ToInsp :: Queue  -> ToDevice($InspPort,METHOD LINUX);

//Counters
InCounter :: AverageCounter;
IpCounter, ArpReplyCounter, ArpQueryCounter, InCounterTotal :: Counter;
ICMPCounter, TCPCounter, IPDropCounter, HTTPAllowCounter, ToPUTInspCounter, DropCounter:: Counter;
GETCounter, HeadCounter, DeleteCounter, OptionsCounter, ConnectCounter, TraceCounter, UnknownCounter :: Counter;
PasswdCounter, LogCounter,InsertCounter,UpdateCounter, DeleteKCounter,LegalCounter, DiscardCounter :: Counter;

//Classifiers
IpArpClassifier :: Classifier(12/0800,	        // IP packets,
                        12/0806 20/0001,	// ARP Queries,
			12/0806 20/0002,	// ARP Replies,
                        -                       // Other packets except for ARP and IP packets
);      

IpPacketClassifier :: IPClassifier(
        proto icmp,     //      ICMP Packets
        port http,     //      HTTP Packets
        proto tcp,      //      TCP Packets
        -               //      Other Packets
);

HTTPClassifier :: Classifier(
        66/505554,              //   PUT
        66/504F5354,            //   POST
        66/474554,              //   GET
        66/48454144,            //   HEAD
        66/44454C455445,        //   DELETE
        66/4F5054494F4E53,      //   OPTIONS
        66/434F4E4E454354,      //   CONNECT
        66/5452414345,          //   TRACE
        -
);

PUTClassifier :: Classifier(
        209/636174202F6574632F706173737764,     //      cat /etc/passwd
        209/636174202F7661722F6C6F672F,         //      cat /var/log/
        208/494E53455254,                       //      INSERT
        208/555044415445,                       //      UPDATE
        208/44454C455445,                       //      DELETE
        -
);

//Discard queue for total Discards Counter
DiscQueue :: Queue -> DiscardCounter -> Discard;

FromSw2 -> InCounter -> InCounterTotal -> IpArpClassifier;

IpArpClassifier[0] -> Print("IP packet received from switch 2", 0) -> Strip(14) -> CheckIPHeader -> IpCounter -> IpPacketClassifier;   //      Forward IP packets to LBS with an offset of 14 
IpArpClassifier[1] -> Print("ARP Query received from switch 2", 0) ->  ArpQueryCounter -> ToLbs;                               //      Forward arp querys to LBS
IpArpClassifier[2] -> Print("ARP Reply received from switch 2", 0) ->  ArpReplyCounter -> ToLbs;                               //      Forward arp querys to LBS
IpArpClassifier[3] -> DropCounter -> DiscQueue;                                                                                 //      Drop packets that don't meet the two criterias

IpPacketClassifier[0] -> Unstrip(14) -> Print("ICMP packet received from switch 2", 0) -> ICMPCounter -> ToLbs;
IpPacketClassifier[1] -> Unstrip(14) -> Print("TCP packet received from switch 2", 0) -> TCPCounter -> HTTPClassifier;
IpPacketClassifier[2] -> Unstrip(14) -> Print("TCP Syn", 0) -> ToLbs;
IpPacketClassifier[3] -> Unstrip(14) -> Print("Unwanted packet IP packet from switch 2", 0) -> IPDropCounter -> DiscQueue;

HTTPClassifier[1] -> Print("POST Method received Allowed",0) -> HTTPAllowCounter -> ToLbs;
HTTPClassifier[0] -> Print("PUT Method received Allowed",0) -> ToPUTInspCounter -> PUTClassifier;
HTTPClassifier[2] -> Print("GET Method received Disallowed",0) -> GETCounter -> ToInsp;
HTTPClassifier[3] -> Print("HEAD Method received Disallowed",0) -> HeadCounter -> ToInsp;
HTTPClassifier[4] -> Print("DELETE Method received Disallowed",0) -> DeleteCounter -> ToInsp;
HTTPClassifier[5] -> Print("OPTIONS Method received Disallowed",0) -> OptionsCounter -> ToInsp;
HTTPClassifier[6] -> Print("CONNECT Method received Disallowed",0) -> ConnectCounter -> ToInsp;
HTTPClassifier[7] -> Print("TRACE Method received Disallowed",0) -> TraceCounter -> ToInsp;
// HTTPClassifier[7] -> Print("TCP Acks") -> ToLbs;
HTTPClassifier[8] -> Print("TCP Syn", 0) -> UnknownCounter -> ToLbs;

PUTClassifier[0] -> Print("Keyword cat /etc/passwd FOUND", 0) -> PasswdCounter -> DiscQueue;
PUTClassifier[1] -> Print("Keyword cat /var/log/ FOUND", 0) -> LogCounter -> DiscQueue;
PUTClassifier[2] -> Print("Keyword INSERT FOUND", 0) -> InsertCounter ->DiscQueue;
PUTClassifier[3] -> Print("Keyword UPDATE FOUND", 0) -> UpdateCounter ->DiscQueue;
PUTClassifier[4] -> Print("Keyword DELETE FOUND", 0) -> DeleteKCounter ->DiscQueue;
PUTClassifier[5] -> Print("No keywords FOUND LEGAL PUT", 0) -> LegalCounter ->ToLbs;

IpArpClassifierOut :: Classifier(12/0800,       // IP packets,
                                12/0806 20/0001,	// ARP Queries,
			                    12/0806 20/0002,	// ARP Replies,
                        -                       // Other packets except for ARP and IP packets
);      

// IpPacketClassifierOut :: IPClassifier(
//         proto icmp,
//         proto tcp,
//         -
// );

// From Load Balancer to Switch 2 


// ArpQueryCounterOut, ArpReplyCounterOut,TCPCounterOut, ICMPCounterOut, DropCounterLBS, IpReplyCounter :: Counter
ArpQueryCounterOut, ArpReplyCounterOut, OutCounterTotal, OutCounter, IpReplyCounter, DropCounterLBS :: Counter;
FromLbs -> OutCounter -> OutCounterTotal -> IpArpClassifierOut;

IpArpClassifierOut[2] -> Print("ARP Reply received from LBS", 0) -> ArpReplyCounterOut -> ToSw2;
IpArpClassifierOut[1] -> Print("ARP Query received from LBS", 0) -> ArpQueryCounterOut -> ToSw2;
IpArpClassifierOut[0] -> Print("IP packet received from LBS", 0) -> IpReplyCounter -> ToSw2;
IpArpClassifierOut[3] ->  DropCounterLBS -> DiscQueue; 

// IpPacketClassifierOut[0] -> Unstrip(14) -> Print("ICMP Packet received from LBS", 0) -> ICMPCounterOut -> ToSw2;
// IpPacketClassifierOut[1] -> Unstrip(14) -> Print("TCP Packet received from LBS", 0) -> TCPCounterOut -> ToSw2;
// IpPacketClassifierOut[2] -> Print("Unwanted IP Packet", 0) -> DiscQueue;

DriverManager(
        pause
        // ,
        // print
        // "
        // =================== IDS Report ===================
        // Total # of input packets: $(InCounterTotal.count)
        // Total # of output packets: $(OutCounterTotal.count)
        // Total # of ARP Query requests: $(ArpQueryCounter.count)
        // Total # of ARP Reply: $(ArpReplyCounter.count)
        // Total # of ICMP Packets Received: $(ICMPCounter.count)
        // Total # of TCP Packets Received: $(TCPCounter.count)
        // Total # of IP Packets Dropped: $(IPDropCounter.count)
        // Total # of HTTP POST Allowed: $(HTTPAllowCounter.count)
        // Total # of HTTP PUT Packets : $(ToPUTInspCounter.count)
        // Total # of HTTP DELETE Packets Dropped: $(DeleteCounter.count)
        // Total # of HTTP GET Packets Dropped: $(GETCounter.count)
        // Total # of HTTP HEAD Packets Dropped: $(HeadCounter.count)
        // Total # of HTTP OPTIONS Packets Dropped: $(OptionsCounter.count)
        // Total # of HTTP CONNECT Packets Dropped: $(ConnectCounter.count)
        // Total # of HTTP TRACE Packets Dropped: $(TraceCounter.count)
        // Total # of HTTP Packets Dropped: $(UnknownCounter.count)
        // Total # of PUT Packets with know injections $(add $(PasswdCounter.count) $(LogCounter.count) $(InsertCounter.count) $(UpdateCounter.count) $(DeleteKCounter.count))
        // Total # of PUT Packets that were legal: $(LegalCounter.count)
        // Total # of dropped packets: $(DiscardCounter.count)
        // ==================================================
        // "
)




