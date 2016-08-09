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

from dnslib import CLASS, QTYPE, RDMAP, DNSRecord, DNSHeader

# Update dnslib's CLASS variable to hold class 0x8001 - IN + Cache Flush for mDNS.
# Also, when *receiving* a query with the top bit set (0x8000), the response is
# allowed to be transmitted via unicast rather than multicast.
CLASS.forward[0x8001] = "IN_mDNS"
CLASS.reverse["IN_mDNS"] = 0x8001

# Update dnslib's QTYPE variable to allow SRV lookups.
QTYPE.forward[33] = "SRV"
QTYPE.reverse["SRV"] = 33

import dns.resolver, dns.message, dns.rdatatype, dns.opcode
import socket, struct, sys

from util import SRV, get_mdns_socket

# Update dnslib's RDMAP to handle SRV records using our custom class.
RDMAP["SRV"] = SRV

# Cache of lookups - helps us avoid hitting the DNS server over and over for the
# same DNS name (which, to be honest, seems to happen a lot with mDNS)
#
# You can actually use this to spoof a few names on your own network if you so
# desire - for example:
# lookupCache = { ("host.local.", QTYPE.A)) : A("1.2.3.4") }
# Note the trailing full stop.
lookupCache = {}

# Grab an mDNS socket ready for use
sock = get_mdns_socket()

print "Now listening for mDNS queries..."

# Main loop - we listen for queries on the local network, and perform a unicast
# lookup on each one. If there are no records for a given lookup, we just ignore
# it and continue. If there are records though, we'll create an mDNS response
# and send that back out.
while True:
    # 8 KB should be enough for an mDNS message...
    buf, remote = sock.recvfrom(8192)
    try:
        msg = dns.message.from_wire(buf)
    except KeyboardInterrupt:
        break
    except:
        continue
    
    # We're only looking at queries - everything else isn't worth looking at.
    if msg.opcode() == dns.opcode.QUERY:
        # Forget about answers, we only want questions.
        if len(msg.answer):
            continue
        print "mDNS query from %s:%d" % remote
        
        # Completed forward lookups.
        lookups = []
        
        # Forward the queries to the unicast server.
        for question in msg.question:
            qname = str(question.name)
            print "\tfor %s [%d]" % (qname, question.rdtype)
            
            unicastResponse = question.rdclass == getattr(CLASS, "IN_mDNS")
            
            # Handle errors from the lookup - don't respond if we can't lookup.
            try:
                # Attempt to use the lookup cache if possible
                rdata = lookupCache.get((qname, question.rdtype))
                if rdata is None:
                    # Forward lookup, using default DNS servers.
                    answer = dns.resolver.query(qname, question.rdtype)
                    for record in answer:
                        tmp = to_wire_helper()
                        record.to_wire(tmp)
                        rdata = RD.parse(tmp, tmp.size())
                        
                        lookupCache[(qname, question.rdtype)] = rdata
                
                lookups += [[qname, question.rdtype, rdata, unicastResponse]]
            except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NoMetaqueries):
                print "\tNo result for a lookup of type %d for %s" % (question.rdtype, str(question))
        
        if len(lookups):
            # Create the DNS message to send out
            resp = None
            uresp = None
            
            # We just assume the response should be in the IN class for now.
            for dnsname, rdtype, response, unicast in lookups:
                if not response is None:
                    if dnsname[-1] == ".":
                        dnsname = dnsname[:-1]
                    
                    if unicast:
                        if uresp is None:
                            uresp = DNSRecord(DNSHeader(id = 0, bitmap = 0x8400))
                        r = uresp
                    else:
                        if resp is None:
                            resp = DNSRecord(DNSHeader(id = 0, bitmap = 0x8400))
                        r = resp
                    
                    r.add_answer(RR(dnsname, rdtype, getattr(CLASS, "IN_mDNS"), rdata = response, ttl = 120))
            
            # Send out the response to the group
            if not resp is None:
                sock.sendto(resp.pack(), (MDNS_DESTINATION, MDNS_PORT))
            
            # Send out unicast responses
            if not uresp is None:
                sock.sendto(uresp.pack(), remote)
            
            # Tell the user how many records were returned.
            print "%d records in response" % (len(lookups),)

