#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable
from scapy.all import Ether, IP, ARP

# From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

# From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

# From /usr/include/linux/in.h:
IPPROTO_ICMP = 1 # Internet Control Message Protocol
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward: bool):
        super(Host, self).__init__()

        self._ip_forward = ip_forward
        self._arp_table = {}
        self.pending = []

        # TODO: Initialize self.fowarding_table
	# self.forwarding_table =

        routes = json.loads(os.environ['COUGARNET_ROUTES'])

	#TODO: Create a for loop to add entries into the forwarding table using prefix, intf, and next_hop
	#for prefix, intf, next_hop in routes:



        for intf in self.physical_interfaces:
            prefix = '%s/%d' % \
                    (self.int_to_info[intf].ipv4_addrs[0],
                            self.int_to_info[intf].ipv4_prefix_len)
            self.forwarding_table.add_entry(prefix, intf, None)


    def _handle_frame(self, frame: bytes, intf: str) -> None:
        eth = Ether(frame)
        if eth.dst == 'ff:ff:ff:ff:ff:ff' or \
                eth.dst == self.int_to_info[intf].mac_addr:

            if eth.type == ETH_P_IP:
                self.handle_ip(bytes(eth.payload), intf)
            elif eth.type == ETH_P_ARP:
                self.handle_arp(bytes(eth.payload), intf)
        else:
            self.not_my_frame(frame, intf)
        

    def handle_ip(self, pkt: bytes, intf: str) -> None:
        ip = IP(pkt)
        all_addrs = []

	#Parse out all destination IP address in the packet
        for intf1 in self.int_to_info:
            all_addrs += self.int_to_info[intf1].ipv4_addrs

	#Determine if this host is the final destination for the packet, based on the destination IP address
        if ip.dst == '255.255.255.255' or \
                ip.dst in all_addrs:
	   #TODO: If the packet is destined for this host, based on the tests in the previous bullet, then call another method to handle the payload, depending on the protocol value in the IP header.
	   #Hint: For type TCP (IPPROTO_TCP = 6), call handle_tcp(), passing the full IP datagram, including header.
           #Hint: For type UDP (IPPROTO_UDP = 17), call handle_udp(), passing the full IP datagram, including header. Note that if the protocol is something other than TCP or UDP, you can simply ignore it.

        else:
	#TODO: If the destination IP address does not match any IP address on the system, and it is not the IP broadcast, then call not_my_packet(), passing it the full IP datagram and the interface on which it arrived.



    def handle_tcp(self, pkt: bytes) -> None:
        pass

    def handle_udp(self, pkt: bytes) -> None:
        pass

    def handle_arp(self, pkt: bytes, intf: str) -> None:
	arp = ARP(pkt)

        #TODO: Determine whether the ARP packet is an ARP request or an ARP response (i.e., using the opcode field), then call handle_arp_response() or handle_arp_request() accordingly. 
	#if arp.op ==


   def handle_arp_response(self, pkt: bytes, intf: str) -> None:
        pkt = ARP(pkt)
        self._arp_table[pkt.psrc] = pkt.hwsrc
        for pkt1, next_hop1, intf1 in self.pending[:]:
            if next_hop1 == pkt.psrc and intf1 == intf:
                eth = Ether(src=self.int_to_info[intf1].mac_addr, dst=self._arp_table[next_hop1], type=ETH_P_IP)
                frame = eth / pkt1
                self.send_frame(bytes(frame), intf1)
                self.pending.remove((pkt1, next_hop1, intf1))

    def handle_arp_request(self, pkt: bytes, intf: str) -> None:
        pkt = ARP(pkt)
        if pkt.pdst == self.int_to_info[intf].ipv4_addrs[0]:
            self._arp_table[pkt.psrc] = pkt.hwsrc
	    #TODO: build and send an Ethernet frame containing the ARP response
	    # eth =
	    # arp = 
	    # frame =
            self.send_frame(bytes(frame), intf) 

	

    def send_packet_on_int(self, pkt: bytes, intf: str, next_hop: str) -> None:
        print(f'Attempting to send packet on {intf} with next hop {next_hop}:\n{repr(pkt)}')
 	
	#check the host-wide ARP table to see if a mapping already exists
	if next_hop in self._arp_table:
	    #TODO: build an Ethernet frame
            #eth = 
            #frame = 
            self.send_frame(bytes(frame), intf)

	#if no mapping exists
        else:
            #eth = 
            #arp = 
            #frame = 
            self.send_frame(bytes(frame), intf)
            self.pending.append((pkt, next_hop, intf))



    def send_packet(self, pkt: bytes) -> None:
        print(f'Attempting to send packet:\n{repr(pkt)}')
        ip = IP(pkt)
        intf, next_hop = self.forwarding_table.get_entry(ip.dst)
        if next_hop is None:
            next_hop = ip.dst
        if intf is None:
            return
        self.send_packet_on_int(pkt, intf, next_hop)



    def forward_packet(self, pkt: bytes) -> None:
        ip = IP(pkt)
        ip.ttl -= 1
        if ip.ttl <= 0:
            return
        self.send_packet(bytes(pkt))

    def not_my_frame(self, frame: bytes, intf: str) -> None:
        pass

    def not_my_packet(self, pkt: bytes, intf: str) -> None:
        #return #XXX
        if self._ip_forward:
            self.forward_packet(pkt)
        else:
            pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    with Host(args.router) as host:
        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()

