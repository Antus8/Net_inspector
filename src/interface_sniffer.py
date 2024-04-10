#!/usr/bin/env python

import sys
import rospy
from scapy.all import *


class PacketSniffer():
    def __init__(self, network_interface):
        self.net_interface = network_interface
        
        self.intercept_packets(self.net_interface)


    def packet_callback(self, packet):
        if IP in packet:
            sender_ip = packet[IP].src
            if sender_ip == "34.120.51.25":
                packet_size = len(packet)
                packet_data = packet.summary()

                if TCP in packet:
                    payload_size = len(packet[TCP].payload)
                elif UDP in packet:
                    payload_size = len(packet[UDP].payload)
                elif ICMP in packet:
                    # Handle ICMP packets
                    payload_size = 0    
                
                rospy.loginfo(f"Sender IP: {sender_ip} | Packet Size: {payload_size} bytes")
                # rospy.loginfo(packet.sprintf("%IP.len%"))
                # print packet.sprintf("%.time% %-15s, IP.src% -> %-15s,IP.dst%  %IP.chksum% ""%03xr, IP.proto% %r, TCP.flags% \n\n")


        # sender_ip = packet[IP].src
        # packet_size = len(packet)
        # self.total_bytes += packet_size
        
        # if self.start_time is None:
        #     self.start_time = time.time()
        # else:
        #     end_time = time.time()
        #     duration = end_time - self.start_time
        #     bps = self.total_bytes / duration
        #     rospy.loginfo(f"Sender IP: {sender_ip} | Bytes per Second: {bps:.2f}")
                


    def intercept_packets(self, interface):
        try:
            sniff(iface=interface, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            print("Packet interception stopped.")
            sys.exit(0)
        

def main():
    rospy.init_node('network_sniffer_node')
    
    net_interface = rospy.get_param('~network_interface', 'wlp4s0')
    sniffer = PacketSniffer(net_interface)

    while not rospy.is_shutdown():
        rospy.spin()
    sys.exit(0)


if __name__ == "__main__":
    main()
