#!/usr/bin/python

import socket, sys
from struct import *

class TCPHeader():
    #TCP header class. Thanks to Silver Moon for the flags calculation and packing order
    #This was designed to be re-used. You might want to randomize the seq number
    #get_struct performs packing based on if you have a valid checksum or not
    def __init__(self,src_port=54311,dst_port=80,seqnum=1000,acknum=0,data_offset=80,fin=0,syn=1,rst=0,psh=0,ack=0,urg=0,window=5840,check=0,urg_ptr=0):
        self.order = "!HHLLBBHHH" #!=network(big-endian), H=short(2), L=long(4),B=char(1) 
        self.src_port = src_port
        self.dst_port = dst_port
        self.seqnum = seqnum
        self.acknum = acknum
        self.data_offset = data_offset #size of tcp header; size is specified by 4-byte words; This is 80 decimal, which is 0x50, which is 20bytes (5words*4bytes).
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg
        self.window = socket.htons(window)
        self.check = check
        self.urg_ptr = urg_ptr
    def flags(self):
        return self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh <<3) + (self.ack << 4) + (self.urg << 5)
    def get_struct(self,check=False,checksummed=False):
        if check != False: self.check = check
        if checksummed:
            return pack('!HHLLBBH',self.src_port,self.dst_port,self.seqnum,self.acknum,self.data_offset,self.flags(),self.window)+pack('H',self.check)+pack('!H',self.urg_ptr)
        else:
            return pack(self.order,self.src_port,self.dst_port,self.seqnum,self.acknum,self.data_offset,self.flags(),self.window,self.check,self.urg_ptr)

def checksum(msg):
    #Shoutout to Silver Moon @ binarytides for this checksum algo.
    sum = 0
    for i in range(0,len(msg),2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        sum = sum + w
    
    sum = (sum>>16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    sum = ~sum & 0xffff
    return sum

def tcp_checksum(source_ip,dest_ip,tcp_header,user_data=''):
    #Calculates the correct checksum for the tcp header
    tcp_length = len(tcp_header) + len(user_data)
    ip_header = pack('!4s4sBBH',socket.inet_aton(source_ip),socket.inet_aton(dest_ip),0,socket.IPPROTO_TCP,tcp_length) #This is an IP header w/ TCP as protocol.
    packet = ip_header + tcp_header + user_data #Assemble the packet (IP Header + TCP Header + data, and then send it to checksum function)
    return checksum(packet)

def get_source_ip(dst_addr):
    try:
        return [(s.connect((dst_addr, 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    except Exception:
        sys.stderr.write("Something went wrong in get_source_ip, results might be wrong\n")

def send_raw_syn(dest_ip,dst_port):
    #Use raw sockets to send a SYN packet.
    #If you want, you could use the IP header assembled in the tcp_checksum function to have a fully custom TCP/IP stack
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) #Using IPPROTO_TCP so the kernel will deal with the IP packet for us. Change to IPPROTO_IP if you want control of IP header as well
    except Exception:
        sys.stderr.write("Error creating socket in send_raw_syn\n")
    src_addr = get_source_ip(dest_ip) #This gets the correct source IP. Just in case of multiple interfaces, it will pick the right one
    src_port = 54321
    make_tcpheader = TCPHeader(src_port,dst_port)
    tcp_header = make_tcpheader.get_struct()
    packet = make_tcpheader.get_struct(check=tcp_checksum(src_addr,dest_ip,tcp_header),checksummed=True)
    try: s.sendto(packet,(dest_ip,0))
    except Exception: sys.stderr.write("Error utilizing raw socket in send_raw_syn\n")

if len(sys.argv) < 3:
	print("Usage:\n\n knock ip port1 port2 (port3 ...)")
	exit()

ip = sys.argv[1]
knockports = sys.argv[2:]

print("=== knocking {} ===".format(ip))
for port in knockports:
	send_raw_syn(ip,int(port))
	print("::: {}".format(port))



