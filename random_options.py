#!/usr/bin/python

from scapy.all import *
from scapy.volatile import *
from scapy.layers.inet import _IPOption_HDR

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
	fields_desc = [ _IPOption_HDR, 
			FieldLenField("length", None, fmt="B", length_of="data", adjust=lambda pkt,l:l+2),
			StrField("data", "")
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
			# Wonder whether any IP stacks blow up if you send them 
			# an infinite supply of fragmented IP 
			# packets that have too much header to pass any data.  
			# Or for that matter, ones with fragmented 
			# layer 4 headers.  There's nothing in IP that makes that impossible.

		# Oh jeez, is there even an IPOption_Type_Unknown?  Maybe that'd be the best thing to do.
		optionLength = RandIPOptions.optionLengths.get(optionNumber, RandNum(0, ((64-20)/self.size) - 2))

		if(optionLength == 0):
			optionValue = ''
		else:
			optionValue = RandBin(size=optionLength)
		op.append(IPOption_Numerical_Type(option_number = optionNumber, option_data = optionValue))
		return op

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
