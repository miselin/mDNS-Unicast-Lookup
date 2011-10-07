#!/usr/bin/env python
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

from dnslib import *

# Update dnslib's CLASS variable to hold class 0x8001 - IN + Cache Flush for mDNS.
CLASS.forward[0x8001] = "IN mDNS"
CLASS.reverse["IN mDNS"] = 0x8001

import dns.resolver, dns.message, dns.rdatatype, dns.opcode
import socket, struct, sys

# Multicast address for mDNS
MDNS_DESTINATION = '224.0.0.251'
MDNS_PORT = 5353

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

print "Now listening for mDNS queries..."

# Main loop - we listen for queries on the local network, and perform a unicast
# lookup on each one. If there are no records for a given lookup, we just ignore
# it and continue. If there are records though, we'll create an mDNS response
# and send that back out.
while True:
    # 8 KB should be enough for an mDNS message...
    buf, remote = sock.recvfrom(8192)
    msg = dns.message.from_wire(buf)
    
    # We're only looking at queries - everything else isn't worth looking at.
    if msg.opcode() == dns.opcode.QUERY:
        print "mDNS query %s:%s" % remote
        
        # Completed forward lookups.
        lookups = []
        
        # Forward the queries to the unicast server.
        for question in msg.question:
            print "\t%s [%d]" % (str(question), question.rdtype)
            
            # Handle errors from the lookup - don't respond if we can't lookup.
            try:
                # TODO: handle more than A records.
                if question.rdtype == dns.rdatatype.A:
                    # Forward lookup, using default DNS servers.
                    answer = dns.resolver.query(str(question.name), question.rdtype)
                    for record in answer:
                        lookups += [[str(question.name), question.rdtype, record.address]]
            except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                print "\tNo result for a lookup of type %d for %s" % (question.rdtype, str(question))
        
        if len(lookups):
            # Create the DNS message to send out
            resp = DNSRecord(DNSHeader(id = 0, bitmap = 0x8400))
            
            # All responses will be in the IN mDNS class; whereas the actual
            # response type may not always be an A record...
            # TODO: handle non-A records.
            for dnsname, rdtype, response in lookups:
                resp.add_answer(RR(dnsname, rdtype, CLASS.lookup("IN mDNS"), rdata = A(response), ttl = 120))
            
            # Send out the response to the group
            sock.sendto(resp.pack(), (MDNS_DESTINATION, MDNS_PORT))

