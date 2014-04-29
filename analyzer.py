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
	def find_layer_commonality(self, packet_list, selector):
		layerslice = map(selector, packet_list) 
		layerslice = filter(lambda p: p is not None, layerslice)
		if len(layerslice) <= 0:
			return []
		return list(reduce(lambda p, q: set (p) & set (q), layerslice))	
