from itertools import groupby

class Analyzer():
	irrelevant = []
	relevant = []
	succeeded = []
	failed = []
	unclassifiable = []
	def __init__(self, packets, success, failure, relevance): #optional print
		self.relevant = relevance(packets)
		self.succeeded = success(self.relevant)
		self.failed = failure(self.relevant)
		self.irrelevant = list(set(packets) ^ set(self.relevant))
		self.unclassifiable = list(set(self.relevant) ^ (set(self.failed) | set(self.succeeded)))
	def intersection(packet_list, selector):
		l = map(selector, packet_list) 
		l = filter(lambda p: p is not None, l)
		if len(l) <= 0:
			return []
		return list(reduce(lambda p, q: set (p) & set (q), l))	
	def correlate(self, packet_list, selector, grouper):
		l = map(selector, packet_list) 
		l = sorted(reduce(operator.add, filter(lambda p: p is not None, l)))
		if len(l) <= 0:
			return []

		found = {}
		for key, group in groupby(l, grouper):
			for thing in group:
				#print "A %s is a %s." % (thing[1], key)
				if key in found:
					found[key] = found[key] + 1
				else:
					found[key] = 1

		return found
