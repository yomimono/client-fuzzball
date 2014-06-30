import struct
import operator 
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP,TCP,IP
from scapy.base_classes import Net

# map(get_request_or_response_type, map (lambda p: p[0].getlayer(Raw).load, map(lambda p: filter(lambda q: q.getlayer(Raw), p), happytimes))

# for use with packetlist.sessions(), which by default separates halves of a conversation
# and uses a string key
def session_extractor(p):
	if 'TCP' in p:
		src_spec = (p.sport, p.getlayer(IP).src)
		dst_spec = (p.dport, p.getlayer(IP).dst)
		in_order = sorted([src_spec, dst_spec])
		return (in_order[0], in_order[1])
	return 'Other'

# return true for a packetList that contains a complete conversation.
# a full conversation consists of an initial 3-way handshake
# and a final double FIN -> ACK close.
# no promises are made or implied about payloads within that
# conversation.
def isset(packet, number):
	return packet.haslayer(TCP) and packet.getlayer(TCP).flags & number == number

def echo_echoed(packetList):
	# true if payloads come in exactly corresponding pairs
	# client is the SYN sender
	synPackets = packetList.filter(lambda p: p.haslayer(TCP) and p.getlayer(TCP).flags == 2)
	if len(synPackets) == 0:
		return False
	client = synPackets[0][IP].src
	server = synPackets[0][IP].dst
	payloads = packetList.filter(lambda p: p.haslayer(Raw))
	client_payloads = map(lambda p: p.getlayer(Raw).load, payloads.filter(lambda p: p[IP].src == client))
	server_payloads = map(lambda p: p.getlayer(Raw).load, payloads.filter(lambda p: p[IP].src == server))

	if(len(client_payloads) > len(server_payloads)):
		return False

	# each payload sent by the client should be matched by a payload echoed back from the server
	for index in range(0, len(client_payloads) - 1):
		if not client_payloads[index] == server_payloads[index]:
			return False

	#all matches were present
	return True
		

# TODO: enforce sender identities & seq/ack numbers more fully.
def full_conversation(packetList): 
	syns = packetList.filter(lambda p: isset(p, 2))
	synacks = packetList.filter(lambda p: isset(p, 18))
	acks = packetList.filter(lambda p: isset(p, 16))
	fins = packetList.filter(lambda p: isset(p, 1))
	if(len(syns) < 1 or len(synacks) < 1 or len(acks) < 4 or len(fins) < 2):
		return False
	syn_ack_seq_no = synacks[-1].getlayer(TCP).seq
	syn_ack_ack = packetList.filter(lambda p: p.getlayer(TCP).ack == syn_ack_seq_no + 1)
	fin_1_seq_no = fins[0].getlayer(TCP).seq
	fin_1_ack = packetList.filter(lambda p: p.getlayer(TCP).ack == fin_1_seq_no + 1)
	fin_2_seq_no = fins.filter(lambda p: p.src != fins[0].src)[-1].getlayer(TCP).seq 
	fin_2_ack = packetList.filter(lambda p: p.getlayer(TCP).ack == fin_2_seq_no + 1)
	if(len(syn_ack_ack) < 1 or len(fin_1_ack) < 1 or len(fin_2_ack) < 1):
		return False
	return True
