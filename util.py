# encoding: utf-8

# Copyright (c) 2011 Matthew Iselin
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from dnslib import RD
import socket, struct, sys

# Multicast address for mDNS
MDNS_DESTINATION = '224.0.0.251'
MDNS_PORT = 5353

# Gets a multicast socket for use in mDNS queries and responses.
def get_mdns_socket():
    # Set up a listening socket so we can sniff out all the mDNS traffic on the
    # network. REUSEADDR is required on all systems, REUSEPORT also for OS X.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if sys.platform == 'darwin':
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('', MDNS_PORT))

    # Join the multicast group, prepare to receive packets from it.
    mreq = struct.pack("4sl", socket.inet_aton(MDNS_DESTINATION), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
    return sock

# SRV records are not supported in dnslib, so we'll just go ahead and implement
# them here for now...
class SRV(RD):
    @classmethod
    def parse(cls,buffer,length):
        (prio, weight, port,) = buffer.unpack("!HHH")
        target = buffer.decode_name()
        return cls(target, prio, weight, port)
    
    def __init__(self, target, prio = 10, weight = 10, port = 0):
        target = str(target)
        
        if target[-1] == ".":
            target = target[:-1]
        
        self.target = target
        self.prio = prio
        self.weight = weight
        self.port = port

    def pack(self,buffer):
        buffer.pack("!HHH", self.prio, self.weight, self.port)
        buffer.encode_name(self.target)
        
    def __str__(self):
        return "%s:%s prio=%d weight=%d" % (self.target, self.port, self.prio, self.weight)

# Aids in converting a given DNS record into wire data for direct integration
# into the response packet.
class to_wire_helper():
    def __init__(self):
        self.data = ""
        self.length = 0
    
    def get(self, length):
        if length > self.length:
            length = self.length
        return self.data[:length]
    
    def size(self):
        return self.length
    
    def write(self, s):
        self.data += s
        self.length += len(s)

# Dummy exception for handline a timeout
class TimeoutException(Exception):
    pass
