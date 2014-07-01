#!/usr/bin/python

from scapy.all import *
from scapy.volatile import *

class RandVariableOptions(RandField):
	def __init__(self, size=None):
		if size is None:
			size = RandNumExpo(0.05)
		self.size = size

class IPOption_Numerical_Type(IPOption):
	def __init__(self, option_number=0, option_data=''):
		self.option_number = option_number
		self.option_data = option_data
	copy_flag = 1 #TODO: probably should parameterize this
	name = "Randomly generated IP Option"
	fields_desc = [ _IP_Option_HDR, 
			FieldLenField("length", None, fmt="B", 
				length_of("data"), adjust=lambda pkt,l:l+2),
			StrField("data", data)
			]


class RandIPOptions(RandVariableOptions):
	optionLengths = {
			0 : 0, 
			1 : 0, 
			2 : 11,
			8 : 4
	}
	
	def _fix(self):
		optionNumber = RandNum(0, 255)
		# not sure what the max number of options is.  there's no pointer in IP, 
			# just a (potentially long) list of options, and no explicit maximum length
			# specified in the protocol (which is why we have fragmentation).
			# There's an upper bound on what we *can* pass - since we need to preserve
			# options when fragmenting (don't we?) a huge wodge of options can mean that no
			# data is allowed to pass?

			# technically, option-type numbers are decomposable further, and the highest 
			# bit indicates whether the option needs to be copied into all fragments.
			# No defined options have this bit set (the options in RFC791 are 0-9)

			# Actually, that understanding's mistaken.  
			# The option-type numbers given in the RFC
			# are meant to inhabit the lower 5 bits of that field, and the copy-to-fragments 
			# field is logically distinct; so no individual option-type 
			# necessarily implies copy-to-fragments
			# (at least, from its addressing; its specification may do so).
			# For now, let's assume any individual option can be 
			# up to the maximum indicable length.

			# oh jeez, I'm such a dip.  4-bit IHL expressing the number of 4-byte words, 
			# so 64 bytes for the header will be the max.
			# 16-bit total length for the packet (including header).

			# Wonder whether any IP stacks blow up if you send them 
			# an infinite supply of fragmented IP 
			# packets that have too much header to pass any data.  
			# Or for that matter, ones with fragmented 
			# layer 4 headers.  There's nothing in IP that makes that impossible.

		# somewhat frustratingly, scapy models TCP options and IP options completely differently,
		# and so we can't easily construct IP options randomly in the same way we did TCP options.
		# We can pass our random data through the parser, 
		# but then we can only send what we ourselves are able to parse,
		# and we'd like to send a wider variety of strange packets than that.

		# Oh jeez, is there even an IPOption_Type_Unknown?  Maybe that'd be the best thing to do.
		optionLength = RandIPOptions.optionLengths.get(optionNumber, RandNum(0, ((64-20)/self.size) - 2))

		if(optionLength == 0):
			optionValue = ''
		else:
			optionValue = RandBin(size=optionLength)
		op.append(

class RandTCPOptions(RandVariableOptions):
	# It's actually probably better to only index 0 and 1 for this, 
	# or maybe to only use the fixed value some percentage of the time
	# for other option numbers.  Checking the parser for the length 
	# of option 2, say, being some number > 4 seems like a useful error case.
	optionLengths = {
			0 : 0,
			1 : 0,
			2 : 4,
			3 : 3,
			4 : 2,
			5 : 10, # TODO: this can be one of 10, 18, 26, 34
			8 : 10,
			14 : 3
			}
	def _fix(self):
		op = []
		for k in range(self.size):
			optionNumber = RandNum(0, 255) 
			optionLength = RandTCPOptions.optionLengths.get(optionNumber, RandNum(0, 60-20-2)) 
			if(optionLength == 0):
				optionValue = ''
			else:
				optionValue = RandBin(size=optionLength)._fix()
			op.append((optionNumber, optionValue))
		return op
