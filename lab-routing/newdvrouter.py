#!/usr/bin/env python3

import asyncio
import json
import socket

NEIGHBOR_CHECK_INTERVAL = 3
DV_TABLE_SEND_INTERVAL = 1
DV_PORT = 5016

from cougarnet.sim.host import BaseHost

from prefix import *
from forwarding_table_native import ForwardingTableNative as ForwardingTable

class DVRouter(BaseHost):
    def __init__(self):
        super(DVRouter, self).__init__()
        ''' You may need to use these to fill in the TODOs below'''
        self.my_dv = {}
        self.neighbor_dvs = {}
        self.forwarding_table = ForwardingTable()
        self._initialize_dv_sock()
        self._link_down_alarm = {}
        self._neighbor_name_to_ip = {}

    def _initialize_dv_sock(self) -> None:
        '''Initialize the socket that will be used for sending and receiving DV
        communications to and from neighbors.
        '''

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('0.0.0.0', DV_PORT))

    def init_dv(self):
        '''Set up our instance to work with the event loop, initialize our DV,
        and schedule our regular updates to be sent to neighbors.
        '''

        loop = asyncio.get_event_loop()

        # register our socket with the event loop, so we can handle datagrams
        # as they come in
        loop.add_reader(self.sock, self._handle_msg, self.sock)

        # Schedule self.send_dv_next() to be called in 1 second and
        # self.update_dv_next() to be called in 0.5 seconds.
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)
        loop.call_later(DV_TABLE_SEND_INTERVAL - DV_TABLE_SEND_INTERVAL / 2,
                self.update_dv_next)

    def _handle_msg(self, sock: socket.socket) -> None:
        ''' Receive and handle a message received on the UDP socket that is
        being used for DV messages.
        '''

        data, addrinfo = sock.recvfrom(65536)
        self.handle_dv_message(data)

    def _send_msg(self, msg: bytes, dst: str) -> None:
        '''Send a DV message, msg, on our UDP socket to dst.'''

        self.sock.sendto(msg, (dst, DV_PORT))

    def handle_dv_message(self, msg: bytes) -> None:
        d = json.loads(msg.decode('utf-8'))
        '''TODO: assign values to neighbor_name, neighbor_ip, and neighbor_dv'''
        '''neighbor_name = '''
        '''neighbor_ip = '''
        
        ''' End TODO'''
        
        if neighbor_name == self.hostname:
            return

        '''TODO: Assign values to self._neighbor_name_to_ip and self.neighbor_dvs '''

        if neighbor_name in self._link_down_alarm:
            '''TODO: Fill in what should happen if the if statement is true. This is the second time you've seen this neighbor in a certain period of time. You might have to check the asyncio library.'''
        loop = asyncio.get_event_loop()

        '''TODO: Fill in the appropriate arguments. Hint: there are 3. Pessimistically believing that I will never see this neighbor again. You might have to check the asyncio library.'''
        '''self._link_down_alarm[neighbor_name] = loop.call_later()'''

    def send_dv_next(self):
        '''Send DV to neighbors, and schedule this method to be called again in
        1 second (DV_TABLE_SEND_INTERVAL).
        '''

        self.send_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)

    def update_dv_next(self):
        '''Update DV using neighbors' DVs.  Then schedule this method to be
        called again in 1 second (DV_TABLE_SEND_INTERVAL).
        '''

        self.update_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.update_dv_next)

    def handle_down_link(self, neighbor: str):
        self.log(f'Link down: {neighbor}')
        del self.neighbor_dvs[neighbor]

    def resolve_neighbor_dvs(self):
        '''Return a copy of the mapping of neighbors to distance vectors, with
        IP addresses replaced by names in every neighbor DV.
        '''

        neighbor_dvs = {}
        for neighbor in self.neighbor_dvs:
            neighbor_dvs[neighbor] = self.resolve_dv(self.neighbor_dvs[neighbor])
        return neighbor_dvs

    def resolve_dv(self, dv: dict) -> dict:
        '''Return a copy of distance vector dv with IP addresses replaced by
        names.
        '''

        resolved_dv = {}
        for dst, distance in dv.items():
            if '/' not in dst:
                try:
                    dst = socket.getnameinfo((dst, 0), 0)[0]
                except:
                    pass
            resolved_dv[dst] = distance
        return resolved_dv

    def update_dv(self) -> None:
        forwarding_table = {}

        # TODO: get neighboring costs
        # neighbor_costs = 

        # initialize DV with distance 0 to own IP addresses
        dv = dict([(intinfo.ipv4_addrs[0], 0) \
                for intinfo in self.int_to_info.values() if intinfo.ipv4_addrs])

        #TODO: Complete the for loop. NOTE: don't try to add a route for local
        for neighbor in self.neighbor_dvs:

        if dv == self.my_dv:
            send_new_dv = False
        else:
            send_new_dv = True

        self.my_dv = dv
        if send_new_dv:
            self.forwarding_table.flush()
            for dst in forwarding_table:
                self.forwarding_table.add_entry(dst, None, forwarding_table[dst])

    def bcast_for_int(self, intf: str) -> str:
        ip_int = ip_str_to_int(self.int_to_info[intf].ipv4_addrs[0])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        ip_bcast_int = ip_prefix_last_address(ip_prefix_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        bcast = ip_int_to_str(ip_bcast_int, socket.AF_INET)
        return bcast

    def send_dv(self) -> None:
        for intf in self.physical_interfaces:
            d = { 'name': self.hostname,
                    'ip': self.int_to_info[intf].ipv4_addrs[0],
                    'dv': self.my_dv }
            d_json = json.dumps(d).encode('utf-8')
            bcast = self.bcast_for_int(intf)
            self._send_msg(d_json, bcast)

def main():
    router = DVRouter()
    router.init_dv()
    router.run()

if __name__ == '__main__':
    main()
