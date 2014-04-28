import struct
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP,IP
from scapy.base_classes import Net

def get_success_xid(packet):
    raw_stuff = packet.getlayer(Raw).load
    if(len(raw_stuff) == 4):
    	return struct.unpack(">L",packet.getlayer(Raw).load)[0]
    else:
    	return 0

def xid_from_success_report_packets(packet_list):
    possible_packets=filter(lambda p: p.haslayer(UDP) and p.haslayer(Raw) and len(p.getlayer(Raw).load) == 4 and not p.haslayer(DHCP), packet_list)
    return map (get_success_xid, possible_packets)
def xid_from_dhcp_messages(packet_list):
	return map(lambda f: f.xid, filter(lambda p: p.haslayer(UDP) and p.haslayer(BOOTP) and p.haslayer(DHCP), packet_list))
def options_array(packet): 
    try:
    	return packet.getlayer(4).options
    except AttributeError:
	return None
def find_disparate_xid(packet_list):
    return list(set(xid_from_dhcp_messages(packet_list)) ^ set(xid_from_success_report_packets(packet_list)))
def find_dhcp_conversation_by_xid(xid, packet_list):
    return packet_list.filter(lambda p: p.haslayer(DHCP) and p.xid == xid)
def get_message_types(options):
    return map(lambda p: delicious_innards(0, p), options)
def get_message_payloads(options):
    return map(lambda p: delicious_innards(1, p), options)
def delicious_innards(index, thing):
	if(type(thing) is tuple and len(thing) > (index)):
		return thing[index]
	else: 
		return thing
def find_and_group_incomplete_conversations(batch):
	problem_xids = find_disparate_xid(batch) #get the problem set
	problem_convos=map (lambda l: (l, find_dhcp_conversation_by_xid(l, batch)), problem_xids)
	return problem_convos
def enumerate_option_types(list_of_packets):
	option_types_encountered=map(get_message_types, filter(lambda p: p is not None, map(options_array, filter(lambda p: p.op == 2, list_of_packets))))
	return (list(set(reduce(operator.add, option_types_encountered))))
def option_types_by_xid(xid, list_of_packets):
	return (xid, enumerate_option_types(list_of_packets))
	# we're mapping over a list of packets.
	# each packet has a list of options, which are themselves tuples.
	# dig out the message types, and make a list of each message type and
	# which xid(s) it was represented in.
def get_dhcp_options_from_conversation(next_batch):
	return map (lambda p: option_types_by_xid(p[0],p[1]), group_by_xid(next_batch))
