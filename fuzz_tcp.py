#!/usr/bin/python
from scapy.all import *
from random_options import RandTCPOptions
import signal

def one_convo(local_host, local_port, remote_host, remote_port, isn):
	current_seq = isn 
	capture_filter = "tcp port " + str(remote_port)
	verbosity = False
	timeout = 5

	ip=IP(src=local_host, dst=remote_host)
	TCP_SYN=fuzz(TCP(sport=local_port, dport=remote_port, flags="S", seq=current_seq, options=RandTCPOptions(size=1)))
	TCP_SYNACK=sr1(ip/TCP_SYN, timeout=timeout, filter=capture_filter, verbose=verbosity)

	if(TCP_SYNACK is None):
		# timed out getting a response.  Give up and try the next run.
		return

	if(TCP_SYNACK[TCP].flags & 18L != 18L):
		print "SYN/ACK not received in response to SYN.  Sending RST and aborting this iteration."
		TCP_RST=fuzz(TCP(sport=local_port, dport=remote_port, flags="R", seq=current_seq, options=RandTCPOptions(size=1)))
		send(ip/TCP_RST)
		return 

	my_ack = TCP_SYNACK.seq + 1
	current_seq = current_seq + 1
	TCP_ACK=fuzz(TCP(sport=local_port, dport=remote_port, flags="A", seq=current_seq, ack=my_ack))
	send(ip/TCP_ACK, verbose=verbosity)

	my_payload="cats bicycles robots tobors\n"
	TCP_PUSH=fuzz(TCP(sport=local_port, dport=remote_port, flags="PA", seq=current_seq, ack=my_ack))
	TCP_RECV=sr1(ip/TCP_PUSH/my_payload, filter=capture_filter, verbose=verbosity) #ACK, possibly with data

	expected_next_seq = my_ack 
	expected_next_ack = current_seq + len(my_payload)

	if(TCP_RECV[TCP].flags & 8L == 8L): #PUSH flag was set, so there's data; ack it
		my_ack = TCP_RECV.seq + len(TCP_RECV[Raw]) #TODO: calculate ourselves
		TCP_RECV_ACK=fuzz(TCP(sport=local_port, dport=remote_port, flags="A", ack=my_ack))
		send(ip/TCP_RECV_ACK, verbose=verbosity)
	else:
		my_ack = TCP_RECV.seq + 1 #TODO: calculate ourselves
	
	current_seq = TCP_RECV[TCP].ack #TODO: calculate ourselves

	TCP_FIN=fuzz(TCP(sport=local_port, dport=remote_port, flags="FA", seq=current_seq,ack=my_ack))
	TCP_FINACK=sr1(ip/TCP_FIN, filter=capture_filter, verbose=verbosity) #we hope.  may not actually be FIN
	current_seq = current_seq + 1

	my_ack = TCP_FINACK.seq + 1 #TODO: calculate this ourselves
	TCP_ACK=fuzz(TCP(sport=local_port, dport=remote_port, flags="A", seq=current_seq, ack=my_ack))
	send(ip/TCP_ACK, verbose=verbosity)

remote_host=sys.argv[1]
#TODO: automatically set local IP to xenbr0 IP
local_host="192.168.2.1"
runs = 0

def conclude(signum, frame):
	run_forever=False

signal.signal(signal.SIGTERM, conclude)

while(runs < 1000):
	one_convo(local_host, random.randint(32000, 55000), remote_host, 7, random.randint(0, 2^32))
	runs = runs + 1
