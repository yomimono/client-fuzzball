import struct
import operator 
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP,TCP,IP
from scapy.base_classes import Net

# convos = domain.sessions(session_extractor)
# convo_values = convos.values()
# sadtimes =  filter(lambda p: not has_request_and_response(p), convo_values)
# payloads = map(lambda p: filter(lambda q: q.getlayer(Raw), p), sadtimes)
# nonempty = filter (lambda p: len(p) > 0, payloads)
# types =  map(get_request_or_response_type, map (lambda p: p[0].getlayer(Raw).load, nonempty))
# (p[0] because it should be in the first data-bearing packet)

# map(get_request_or_response_type, map (lambda p: p[0].getlayer(Raw).load, map(lambda p: filter(lambda q: q.getlayer(Raw), p), happytimes))

def payloads(packetList):
	loadbearing = packetList.filter(lambda p: p.haslayer(Raw))
	return map(lambda p: p.getlayer(Raw).load, loadbearing)

# for use with packetlist.sessions(), which by default separates halves of a conversation
# and uses a string key
def session_extractor(p):
	if 'TCP' in p:
		src_spec = (p.sport, p.getlayer(IP).src)
		dst_spec = (p.dport, p.getlayer(IP).dst)
		in_order = sorted([src_spec, dst_spec])
		return (in_order[0], in_order[1])
	return 'Other'

def has_request(payload):
	components = payload.split('\r\n')
	tokens = components[0].split(' ')
	if(len(tokens) >= 3 and (tokens[2] == 'HTTP/1.1' or tokens[2] == 'HTTP/1.0')):
		return True
	return False

def _get_response_code(payload):
	components = payload.split('\r\n')
	tokens = components[0].split(' ')
	if(len(tokens) >= 3 and tokens[0] == "HTTP/1.1"):
		return tokens[1]
	else:
		return None

def get_response_codes(packetList):
	loadBearing = payloads(packetList)
	if(len(loadBearing) < 2):
		return None
	codes = filter(lambda p: p is not None, map(_get_response_code, loadBearing))
	if len(codes) > 0:
		return codes[0]
	else:
		return None

def get_request_type(payload):
	components = payload.split('\r\n')
	tokens = components[0].split(' ')
	return tokens[0]

def get_path(payload):
	components = payload.split('\r\n')
	tokens = components[0].split(' ')
	return tokens[1]

def has_response(payload):
	components = payload.split('\r\n')
	tokens = components[0].split(' ')
	if(tokens[0] == 'HTTP/1.1' or tokens[0] == 'HTTP/1.0'):
		return True
	return False

def has_request_and_response(packetList): #presumably a convo-separated list
	# a packet list contains both an HTTP request and an HTTP response.
	relevantPackets = packetList.filter(lambda p: p.haslayer(Raw) and p.getlayer(Raw).load) #ignore TCP traffic w/no payloads
	relevantPackets = map(lambda p: p.getlayer(Raw).load, relevantPackets)
	if(len(relevantPackets) < 2): 
		return False
	if any(map(has_response, relevantPackets)) and any(map(has_request, relevantPackets)):
		return True
	return False
