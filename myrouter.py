#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
import time
import ipaddress


class entry_of_forwarding_table(object):
    def __init__(self,network_prefix,network_mask,next_ip,next_interface):
        self.prefix=network_prefix
        self.mask=network_mask
        self.next_ip=next_ip
        self.next_interface=next_interface

class IPv4_item(object):
    def __init__(self,packet_list,request_time,try_number,arprequest,send_interface):
        self.request_time=request_time
        self.try_number=try_number
        self.packet_list=packet_list
        self.arprequest=arprequest
        self.send_interface=send_interface


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.ip_mac={}#cache table
        self.printnum=0
        self.interfaces_list=[i.ipaddr for i in self.net.interfaces()]
        self.forwarding_table=[]
        self.IPv4_wait_queue={}
        for i in self.net.interfaces():
            self.forwarding_table.append(entry_of_forwarding_table(IPv4Network(str(i.ipaddr)+"/"+str(i.netmask),strict=False),i.netmask,None,i.name))
            #self.forwarding_table.append(entry_of_forwarding_table(i.ipaddr,i.netmask,None,i.name))
            #log_info(f"{i.ipaddr}, {i}")
        with open("forwarding_table.txt","r") as input:
            lines=input.readlines()
            for i in lines:
                entry=i.split()
                self.forwarding_table.append(entry_of_forwarding_table(IPv4Network((entry[0]+"/"+entry[1])),entry[1],ip_address(entry[2]),entry[3]))
                #log_info(f"{entry[0]}, {entry[1]}")
                #self.forwarding_table.append(entry_of_forwarding_table(IPv4Address(entry[0]),IPv4Address(entry[1]),IPv4Address(entry[2]),entry[3]))


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        #log_info("111")


        if (packet.has_header(Arp)):
            #import pdb; pdb.set_trace() 
            arp=packet.get_header(Arp)
            eth=packet.get_header(Ethernet)
            if (eth.dst not in [i.ethaddr for i in self.net.interfaces()] and eth.dst!="ff:ff:ff:ff:ff:ff"):
                return
            if (arp.targetprotoaddr not in self.interfaces_list):
                return
            if (self.net.interface_by_name(ifaceName).ethaddr==eth.dst or eth.dst==SpecialEthAddr.ETHER_BROADCAST.value) and eth.ethertype!=EtherType.Vlan:
                #self.ip_mac[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
                #log_info(f"{arp.senderprotoaddr}, {arp.senderhwaddr}, {arp.targetprotoaddr}, {eth.dst}")
                
                if (arp.operation==ArpOperation.Request):
                    self.ip_mac[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
                    for i in self.net.interfaces():
                        if arp.targetprotoaddr==i.ipaddr:
                            reply_packet=create_ip_arp_reply(i.ethaddr,arp.senderhwaddr,i.ipaddr,arp.senderprotoaddr)#because reply,so the target is which send this arp packet
                            self.net.send_packet(ifaceName,reply_packet)
                elif (arp.operation==ArpOperation.Reply): #reply
                    #log_info("aaa")
                    if (arp.senderhwaddr!="ff:ff:ff:ff:ff:ff"):
                        self.ip_mac[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
                    elif arp.senderprotoaddr not in self.ip_mac.keys():
                        return
                    if (arp.senderprotoaddr in self.IPv4_wait_queue.keys()):
                        for target in self.IPv4_wait_queue[arp.senderprotoaddr].packet_list:
                            ethernet=target.get_header(Ethernet)
                            #log_info("aaa")
                            ethernet.dst=self.ip_mac[arp.senderprotoaddr][0]
                            #log_info("777")
                            ethernet.src=self.IPv4_wait_queue[arp.senderprotoaddr].send_interface.ethaddr
                            #log_info("888")
                            if target.has_header(ICMP):
                                IPv4_send_packet=ethernet+target.get_header(IPv4)+target.get_header(ICMP)
                            elif target.has_header(UDP):
                                IPv4_send_packet=ethernet+target.get_header(IPv4)+target.get_header(UDP)
                            if target.has_header(RawPacketContents):
                                IPv4_send_packet+=target.get_header(RawPacketContents)
                            self.net.send_packet(self.IPv4_wait_queue[arp.senderprotoaddr].send_interface,IPv4_send_packet)
                        #log_info(f"asdf{IPv4_send_packet}")
                        del self.IPv4_wait_queue[arp.senderprotoaddr]
                        #del self.IPv4_wait_queue[arp.senderprotoaddr]
                self.printnum+=1
                print("Table Updated {}".format(self.printnum))
                print("IP                     MAC")
                for i in self.ip_mac.keys():
                    print(i,"          ",self.ip_mac[i][0])


        if (packet.has_header(IPv4)):
            #import pdb; pdb.set_trace()
            #log_info("222")
            ipv4=packet.get_header(IPv4)
            ipv4.ttl-=1
            if packet.get_header(Ethernet).dst not in [i.ethaddr for i in self.net.interfaces()]:
                return
            if (ipv4.dst in self.interfaces_list):
                return# do nothing, will be handled in lab5
            else:
                #if (packet.get_header(Ethernet).dst!=SpecialEthAddr.ETHER_BROADCAST.value and packet.get_header(Ethernet).dst!=self.net.interface_by_name(ifaceName).ethaddr):
                #    return
                find_dst=False
                max_length=-1
                for i in self.forwarding_table:
                    #log_info(f"{i.prefix}, {i.mask}, {i.next_ip}")
                    if (int(ipv4.dst)&int(IPv4Address(i.mask))==int(IPv4Address(str(i.prefix).split("/")[0]))): #find
                        find_dst=True
                        #log_info("qwerasdf")
                        #log_info("222")
                        if (i.prefix.prefixlen>max_length):
                            max_length=i.prefix.prefixlen
                            target=i
                #log_info("333")
                if (not find_dst):
                    return#do nothing, will be handled in lab5
                else:
                    #log_info("444")
                    #log_info("bbb")
                    #ipv4.ttl-=1 #in lab5, we should think about how to solve ttl<0
                    w=target.next_ip
                    if (w==None):
                        w=ipv4.dst
                    if (w in self.interfaces_list):
                        return
                    #log_info(f"{w}")
                    if (w in self.ip_mac.keys()):
                        #log_info(f"{w}")
                        #log_info(f"{self.ip_mac[w][0]}, {w}, {ipv4.dst},{self.net.interface_by_name(target.next_interface).ethaddr}, {target.prefix}, {target.prefix.prefixlen}")
                        ethernet=packet.get_header(Ethernet)
                        ethernet.dst=self.ip_mac[w][0]
                        ethernet.src=self.net.interface_by_name(target.next_interface).ethaddr
                        IPv4_send_packet=ethernet+packet.get_header(IPv4)
                        if packet.has_header(ICMP):
                            IPv4_send_packet+=packet.get_header(ICMP)
                        if packet.has_header(UDP):
                            IPv4_send_packet+=packet.get_header(UDP)
                        if packet.has_header(RawPacketContents):
                            IPv4_send_packet+=packet.get_header(RawPacketContents)
                        self.net.send_packet(self.net.interface_by_name(target.next_interface),IPv4_send_packet)
                    else:
                        #log_info("666")
                        #if (target.next_ip==None):
                        #    target.next_ip=ipv4.dst
                        if (w in self.IPv4_wait_queue.keys()):
                            #log_info("777")
                            self.IPv4_wait_queue[w].packet_list.append(packet)
                        else: # send request
                            request_packet=create_ip_arp_request(self.net.interface_by_name(target.next_interface).ethaddr,self.net.interface_by_name(target.next_interface).ipaddr,w)
                            self.net.send_packet(self.net.interface_by_name(target.next_interface),request_packet)
                            self.IPv4_wait_queue[w]=IPv4_item([packet],time.time(),1,request_packet,self.net.interface_by_name(target.next_interface))
                            
        will_be_del=[]
        for i in self.IPv4_wait_queue.keys():
            if (time.time()-self.IPv4_wait_queue[i].request_time>1 and self.IPv4_wait_queue[i].try_number>=5):
                will_be_del.append(i)
                #del self.IPv4_wait_queue[i]
                #self.IPv4_wait_queue[i].clear()
        for i in will_be_del:
            del self.IPv4_wait_queue[i]
        for i in self.IPv4_wait_queue.keys():
            if (time.time()-self.IPv4_wait_queue[i].request_time>1):
                self.IPv4_wait_queue[i].request_time=time.time()
                self.IPv4_wait_queue[i].try_number+=1
                self.net.send_packet(self.IPv4_wait_queue[i].send_interface,self.IPv4_wait_queue[i].arprequest)


        
        #...

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            # will_be_del=[]
            # for i in self.IPv4_wait_queue.keys():
            #     if (time.time()-self.IPv4_wait_queue[i].request_time>1 and self.IPv4_wait_queue[i].try_number>=5):
            #         will_be_del.append(i)
            #         #del self.IPv4_wait_queue[i]
            #         #self.IPv4_wait_queue[i].clear()
            # for i in will_be_del:
            #     del self.IPv4_wait_queue[i]
            # for i in self.IPv4_wait_queue.keys():
            #     if (time.time()-self.IPv4_wait_queue[i].request_time>1):
            #         self.IPv4_wait_queue[i].request_time=time.time()
            #         self.IPv4_wait_queue[i].try_number+=1
            #         self.net.send_packet(self.IPv4_wait_queue[i].send_interface,self.IPv4_wait_queue[i].arprequest)

                    # if (i in self.ip_mac.keys()):
                    #     for j in self.IPv4_wait_queue[i].packet_list:
                    #         ethernet=packet.get_header(Ethernet)
                    #         ethernet.dst=self.ip_mac[target.next_ip][0]
                    #         ethernet.src=self.net.interface_by_name(target.next_interface).ethaddr
                    #         IPv4_send_packet=ethernet+packet.get_header(IPv4)+packet.get_header(ICMP)
                    #         self.net.send_packet(self.net.interface_by_name(target.next_interface),IPv4_send_packet)
            try:
                recv = self.net.recv_packet(timeout=1.0)
                

            except NoPackets:
                will_be_del=[]
                for i in self.IPv4_wait_queue.keys():
                    if (time.time()-self.IPv4_wait_queue[i].request_time>1 and self.IPv4_wait_queue[i].try_number>=5):
                        will_be_del.append(i)
                        #del self.IPv4_wait_queue[i]
                        #self.IPv4_wait_queue[i].clear()
                for i in will_be_del:
                    del self.IPv4_wait_queue[i]
                for i in self.IPv4_wait_queue.keys():
                    #import pdb; pdb.set_trace() 
                    if (time.time()-self.IPv4_wait_queue[i].request_time>1):
                        self.IPv4_wait_queue[i].request_time=time.time()
                        self.IPv4_wait_queue[i].try_number+=1
                        self.net.send_packet(self.IPv4_wait_queue[i].send_interface,self.IPv4_wait_queue[i].arprequest)
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
