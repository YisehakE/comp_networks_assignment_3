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

# Additional constants I included
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff" 
DEFAULT_TARGET_MAC = "00:00:00:00:00:00"
ARP_ADDR_SZ = 6
IPV4_ADDR_SZ = 4

import json
import struct

class Host(BaseHost):
  def __init__(self, ip_forward: bool):
    super().__init__()

    # UPDATED FROM HOSTNEW !
    self._ip_forward = ip_forward
    self._arp_table = {}
    self.pending = []

    self.forwarding_table = ForwardingTable()

    routes = json.loads(os.environ['COUGARNET_ROUTES'])

    for prefix, intf, next_hop in routes:
       self.forwarding_table.add_entry(prefix, intf, next_hop)

    for intf in self.physical_interfaces:
        prefix = '%s/%d' % \
                (self.int_to_info[intf].ipv4_addrs[0],
                self.int_to_info[intf].ipv4_prefix_len)
        self.forwarding_table.add_entry(prefix, intf, None)

      # do any additional initialization here


  def _handle_frame(self, frame: bytes, intf: str) -> None:
    eth = Ether(frame)
    if eth.dst == 'ff:ff:ff:ff:ff:ff' or eth.dst == self.int_to_info[intf].mac_addr:
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
        if ip.dst == '255.255.255.255' or ip.dst in all_addrs:
          if ip.proto == IPPROTO_TCP:
            self.handle_tcp(pkt)
          elif ip.proto == IPPROTO_UDP:
            self.handle_udp(pkt)
        else:
          self.not_my_packet(pkt, intf)
      
  def handle_tcp(self, pkt: bytes) -> None:
      pass

  def handle_udp(self, pkt: bytes) -> None:
      pass

  def handle_arp(self, pkt: bytes, intf: str) -> None:
    arp = ARP(pkt)

    if arp.op == ARPOP_REQUEST:
      self.handle_arp_request(pkt, intf)
    elif arp.op == ARPOP_REPLY:
      self.handle_arp_response(pkt, intf)
   
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

      intf_info = self.int_to_info[intf]
      if pkt.pdst == intf_info.ipv4_addrs[0]:
        self._arp_table[pkt.psrc] = pkt.hwsrc

        sender_ip, target_ip = pkt.pdst, pkt.psrc # Reversed the sender & target ips
        sender_mac, target_mac = intf_info.mac_addr, pkt.hwsrc # Sender mac as interface src and target mac as sender src

        arp_resp = self.create_arp(ARPOP_REPLY, sender_mac, sender_ip, target_mac, target_ip)
        eth = self.create_eth_frame(target_mac, sender_mac, ETH_P_ARP) # TODO: figure out if payload needs to be raw bytes
        frame = eth / arp_resp

        self.send_frame(bytes(frame), intf) 

  def send_packet_on_int(self, pkt: bytes, intf: str, next_hop: str) -> None:
    if next_hop in self._arp_table: # Build ethernet frame right away
      # Step 1: build + send Ethernet frame with IP pkt given along with 2 other attributes:
      dst_mac_addr = self._arp_table[next_hop] # TODO: determine correct form of dest. MAC address
      src_mac_addr = self.int_to_info[intf].mac_addr
      eth = self.create_eth_frame(dst_mac_addr, src_mac_addr, ETH_P_IP)
      frame = eth / IP(pkt)

      print("(REG) Send on int | ip pkt: ", pkt)
      print("(BYTES) Send on int | ip pkt: ", bytes(pkt))
      print("(TRANS) Send on int | ip pkt from bytes to ip", str(IP(pkt)))

      # Step 2: send the frame as byte object along with given interface
      self.send_frame(bytes(frame), intf) # TODO: figure out if wrapping in bytes object is necessary
    else: # Build ethernet frame with ARP request
      # Step 1: create ARP request from interface info
      intf_info = self.int_to_info[intf] # Type - InterfaceInfo

      sender_ip, sender_mac = intf_info.ipv4_addrs[0], intf_info.mac_addr
      target_ip, target_mac = next_hop, DEFAULT_TARGET_MAC
      arp_req = self.create_arp(ARPOP_REQUEST, sender_mac,sender_ip, target_mac, target_ip)

      print("(REG) Send on int | arp req: ", str(arp_req))
      print("(BYTES) Send on int | arp req: ", bytes(arp_req))
      print("(TRANS) Send on int | arp packet from bytes to packet", str(ARP(bytes(arp_req))))



      # Step 2: build + send Ethernet frame with ARP request just created, along with 3 other attributes:
      dst_mac_addr = BROADCAST_MAC # TODO: determine correct form of mac address (i.e bytes or string)

      eth = self.create_eth_frame(BROADCAST_MAC, sender_mac, ETH_P_ARP) # TODO: figure out if payload needs to be raw bytes
      frame = eth / arp_req
      print("(REG) Send on int | Frame w/ arp req: ", str(frame))
      print("(BYTES) Send on int | Frame w/ arp req: ", bytes(frame))
      print("(TRANS) Send on int | Frame w/ arp req: ", str(Ether(frame)))


      # Step 3: send frame & queue this packet along with interface & next_hop ip addr
      self.send_frame(bytes(frame), intf) # TODO: figure out if wrapping in bytes object is necessary
      self.pending.append((pkt, intf, next_hop))

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
      

  # Additional helper functions I included
  def create_arp(self, code, send_mac, send_ip, tar_mac, tar_ip): 
    arp_pkt = ARP(
                  hwtype=ARPHRD_ETHER, 
                  ptype=ETH_P_IP, 
                  hwlen=ARP_ADDR_SZ,
                  plen=IPV4_ADDR_SZ,
                  op=code,
                  hwsrc=send_mac,
                  psrc=send_ip, 
                  hwdst=tar_mac,
                  pdst=tar_ip
              )
    print("Create arp | packet: ", str(arp_pkt))
    return arp_pkt
  
  def create_eth_frame(self, dst_mac, src_mac, type): # TODO: figure out how-to-build frame
    frame = Ether(
                dst=dst_mac,
                src=src_mac,
                type=type
              )
    print("Create eth | frame: ", str(frame))
  
    return frame # TODO: figure out if I need to attach anything before the payload (ref. https://stackoverflow.com/questions/6605118/adding-payload-in-packet)

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
