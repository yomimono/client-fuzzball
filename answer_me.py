import struct

from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP,IP
from scapy.layers.l2 import Ether
from scapy.base_classes import Net 
from scapy.volatile import RandField

from scapy.arch import get_if_raw_hwaddr
from scapy.sendrecv import srp1

class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"
    send_function = staticmethod(sendp)
    def parse_options(self, pool=Net("192.168.1.128/25"), network="192.168.1.0/24",gw="192.168.1.1",
                      domain="localnet", renewal_time=60, lease_time=1800):
        if type(pool) is str:
            pool = Net(pool)
        self.domain = domain
        netw,msk = (network.split("/")+["32"])[:2]
        msk = itom(int(msk))
        self.netmask = ltoa(msk)
        self.network = ltoa(atol(netw)&msk)
        self.broadcast = ltoa( atol(self.network) | (0xffffffff&~msk) )
        self.gw = gw
        if isinstance(pool,Gen):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast]]
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}

    def is_request(self, req):
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1

    def print_reply(self, req, reply):
        print "Reply %s to %s" % (reply.getlayer(IP).dst,reply.dst)

    def make_reply(self, req):        
        mac = req.src
        if type(self.pool) is list:
            if not self.leases.has_key(mac):
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool
            
        repb = req.getlayer(BOOTP).copy()
        repb.op="BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del(repb.payload)
	# without fragmentation, we fail because the packet is too long.
	# with fragmentation, we fail because we're trying to compare 
	# a list to a single object.  The correct answer is probably to 
	# truncate and force the answer not to exceed the size of a packet.
        rep=Ether(dst=mac)/IP(dst=ip)/UDP(sport=req.dport,dport=req.sport)/repb
        return rep

# Fuzzing answering machines don't seem super obvious to construct,
# since we don't have direct access to the layers we're looking at -
# the construction of our delicous packet sandwich is happening at a 
# lower layer, over which we don't have a whole mess of control.
class DHCP_fuzz_am(BOOTP_am):
    function_name="fuzzy_dhcpd"
    test_counter = 0
    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
				# TODO: a way to limit this to a specific MAC or interface;
				# I am NOT A FAN of accidentally serving to all requestors
        if DHCP in req:
            dhcp_options = [(op[0],{1:2,3:5}.get(op[1],op[1]))
                            for op in req[DHCP].options
                            if type(op) is tuple  and op[0] == "message-type"]
	    dhcp_options += RandDHCPOptions(size=1) # parameterize this?  it's a count
	    # of fuzzed options, not of their length, and their length could be any size)

	    dhcp_options += ["end"]
            resp /= DHCP(options=dhcp_options) # stick ourselves into the structure of resp
	    # resp is now the thing that might be too long. how can we check?

	    # also, is fragmentation allowed in dhcp? it seems like it shouldn't be, but 
	    # on the other hand, if PXE actually works this way, I feel like it kinda 
	    # must be.

	    # It's also not clear to me how we can really make any kind of statement about program
	    # correctness in this framework.  I'd really like to take a look at Sculley or Sulley
	    # or whatever it is instead - there may be some way to say "and I fuzzed with this percent 
	    # of coverage with this" rather than just fuzz a bunch and call it good if you didn't 
	    # get anything back.

	    # also, in the absence of problems, we don't check again, which is fairly suboptimal.  
	    # it might be better to write a VM that purposely runs through the state machine.
        print resp.xid
        return resp
    

