import struct
import operator 
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

def find_failed_xids(packet_list): return find_disparate_xid(packet_list)
def find_succeeded_xids(packet_list): 
	return list(set(xid_from_dhcp_messages(packet_list)) & set(xid_from_success_report_packets(packet_list)))

def get_xid(packet):
	if packet.haslayer(DHCP):
		return packet.xid
	if packet.haslayer(UDP) and packet.haslayer(Raw):
		return get_success_xid(packet)
	return None

def relevant_packets(packet_list):
	return packet_list.filter(lambda p: get_xid(p) is not None)

def succeeded_packets(packet_list):
	# return those packets which are part of a successful DHCP transaction or are reports of success
	good_xids = find_succeeded_xids(packet_list)
	return packet_list.filter(lambda p: get_xid(p) is not None and get_xid(p) in good_xids)

def failed_packets(packet_list):
	bad_xids = find_failed_xids(packet_list)
	return packet_list.filter(lambda p: get_xid(p) is not None and get_xid(p) in bad_xids)

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

def is_option_type(packet, number): #TODO: this could be more parameterizable
	return (('message-type', number) in packet.getlayer(DHCP).options)
def find_and_group_incomplete_conversations(batch):
	problem_xids = find_disparate_xid(batch) #get the problem set
	problem_convos=map (lambda l: (l, find_dhcp_conversation_by_xid(l, batch)), problem_xids)
	return problem_convos
def enumerate_option_types(list_of_packets):
	response_packets = list_of_packets.filter(lambda p: p.haslayer(BOOTP) and p.op == 2) #BOOTP response
	all_options_lists = map(options_array, response_packets)
	option_types_encountered = map(get_message_types, all_options_lists)
	if len(option_types_encountered) > 0:
		return list(set(reduce(operator.add, option_types_encountered)))
	else:
		return []
def option_types_by_xid(xid, list_of_packets):
	return (xid, enumerate_option_types(list_of_packets))
	# we're mapping over a list of packets.
	# each packet has a list of options, which are themselves tuples.
	# dig out the message types, and make a list of each message type and
	# which xid(s) it was represented in.
def get_dhcp_options_from_conversation(list_of_packets):
	return map (lambda p: option_types_by_xid(p[0],p[1]), find_and_group_incomplete_conversations(list_of_packets))

def successful_thing_with_analyzer(list_of_packets):  #find common elements between packets, usually 
	#already filtered to be, say, stuff that failed
	return Analyzer().find_commonality(filter( lambda p: ('message-type', 5) in p.getlayer(DHCP).options, list_of_packets), lambda p: p.getlayer(DHCP).options)

def count_options(domain, analyzer):
	return analyzer.correlate(filter(lambda p: p.haslayer(DHCP), domain), lambda p: p.getlayer(DHCP).options, lambda p: delicious_innards(0, p))

def count_payloads(domain, analyzer):
	return analyzer.correlate(filter(lambda p: p.haslayer(DHCP), domain), lambda p: p.getlayer(DHCP).options, lambda p: delicious_innards(1, p))

def count_offer_options(domain, analyzer):
	return analyzer.correlate(filter(lambda p: p.haslayer(DHCP) and is_option_type(p, 2), domain), lambda p: p.getlayer(DHCP).options, lambda p: delicious_innards(0, p))
def count_ack_options(domain, analyzer):
	return analyzer.correlate(filter(lambda p: p.haslayer(DHCP) and is_option_type(p, 5), domain), lambda p: p.getlayer(DHCP).options, lambda p: delicious_innards(0, p))

def only_failed_options(analyzer):
	failed_options = count_options(analyzer.failed, analyzer)
	succeeded_options= count_options(analyzer.succeeded, analyzer)
	return set(failed_options) & (set(failed_options) ^ set(succeeded_options))

def only_succeeded_options(analyzer):
	failed_options = count_options(analyzer.failed, analyzer)
	succeeded_options= count_options(analyzer.succeeded, analyzer)
	return set(succeeded_options) & (set(failed_options) ^ set(succeeded_options))
