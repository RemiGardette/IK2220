// Define the ports
define($PORT_PRIVATE napt-eth2, $PORT_PUBLIC napt-eth1)

// Variables

// Packet counters and rates
counter_out_priv::AverageCounter;
counter_out_pub::AverageCounter;
counter_in_priv::AverageCounter;
counter_in_pub::AverageCounter;

// Counters for different traffic classes
counter_arp_res_priv::Counter;
counter_arp_req_priv::Counter;
counter_tcp_priv::Counter;
counter_icmp_req_priv::Counter;
counter_icmp_res_priv::Counter;
counter_dropped_priv::Counter;
counter_dropped_ip_priv::Counter;
counter_arp_res_pub::Counter;
counter_arp_req_pub::Counter;
counter_tcp_pub::Counter;
counter_icmp_req_pub::Counter;
counter_icmp_res_pub::Counter;
counter_dropped_pub::Counter;
counter_dropped_ip_pub::Counter;

// Input devices
from_private::FromDevice($PORT_PRIVATE, METHOD LINUX, SNIFFER false);
from_public::FromDevice($PORT_PUBLIC, METHOD LINUX, SNIFFER false);

// Output devices
to_private:: Queue -> counter_out_priv -> ToDevice($PORT_PRIVATE);
to_public:: Queue -> counter_out_pub -> ToDevice($PORT_PUBLIC);

// ARP handling, MAC address is arbitrarily chosen
arp_res_priv::ARPResponder(10.0.0.1 10.0.0.1/24 11-11-11-11-11-11);
arp_res_pub::ARPResponder(100.0.0.1 100.0.0.1/24 22-22-22-22-22-22);
arp_req_priv::ARPQuerier(10.0.0.1,11-11-11-11-11-11);
arp_req_pub::ARPQuerier(100.0.0.1,22-22-22-22-22-22);

//Patterns
IPRewriterPatterns(to_pub 10.0.0.1 1024-65535# - -, to_priv 100.0.0.1 1024-65535# - -);

// Rewriters (0/to_priv rewrite the source IP to 10.0.0.1, 1/to_pub rewrite the source IP to 100.0.0.1)
rw_tcp :: IPRewriter(pattern 100.0.0.1 20000-65535 - - 0 1);

rw_icmp :: ICMPPingRewriter(pattern 100.0.0.1 20000-65535 - - 0 1);


// Packet classification
packet_classifier_priv::Classifier(
    12/0806 20/0001,
    12/0806 20/0002,
    12/0800,
    -
);

packet_classifier_pub::Classifier(
    12/0806 20/0001,
    12/0806 20/0002,
    12/0800,
    -
);

// IP classification
ip_classifier_priv::IPClassifier(
    icmp type 0, 
    icmp type 8,
    tcp,
    -
);

ip_classifier_pub::IPClassifier(
    icmp type 0, 
    icmp type 8,
    tcp,
    -
);

// Flow of the packets incoming from the private zone 

from_private -> counter_in_priv -> packet_classifier_priv;

packet_classifier_priv[0] -> counter_arp_res_priv -> arp_res_priv -> to_private;
packet_classifier_priv[1] -> counter_arp_req_priv -> [1]arp_req_priv -> to_private;
packet_classifier_priv[2] -> Strip(14) -> CheckIPHeader -> ip_classifier_priv;
packet_classifier_priv[3] -> counter_dropped_priv -> Discard;

ip_classifier_priv[0] -> counter_icmp_res_priv -> rw_icmp[1] -> to_public;
ip_classifier_priv[1] -> counter_icmp_req_priv -> rw_icmp[1] -> to_public;
ip_classifier_priv[2] -> counter_tcp_priv -> rw_tcp[1] -> [0]arp_req_pub -> to_public;
ip_classifier_priv[3] -> counter_dropped_ip_priv -> Discard;

// Flow of the packets incoming from the outside

from_public -> counter_in_pub -> packet_classifier_pub;

packet_classifier_pub[0] -> counter_arp_res_pub -> arp_res_pub -> to_public;
packet_classifier_pub[1] -> counter_arp_req_pub -> [1]arp_req_pub -> to_public;
packet_classifier_pub[2] -> Strip(14) -> CheckIPHeader -> ip_classifier_pub;
packet_classifier_pub[3] -> counter_dropped_pub -> Discard;

ip_classifier_pub[0] -> counter_icmp_res_pub -> rw_icmp[0] -> to_private;
ip_classifier_pub[1] -> counter_icmp_req_pub -> rw_icmp[0] -> to_private;
ip_classifier_pub[2] -> counter_tcp_pub -> rw_tcp[0] -> [0]arp_req_priv -> to_private;
ip_classifier_pub[3] -> counter_dropped_ip_pub -> Discard;

DriverManager(
    pause
)
