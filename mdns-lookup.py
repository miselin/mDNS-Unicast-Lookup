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

# Little tool to go the other way - do a lookup for a given name via mDNS.
# Can be used to test proxy.py.

from dnslib import CLASS, QTYPE, RDMAP, DNSRecord, DNSHeader, DNSQuestion

# Update dnslib's CLASS variable to hold class 0x8001 - IN + Cache Flush for mDNS.
CLASS.forward[0x8001] = "IN mDNS"
CLASS.reverse["IN mDNS"] = 0x8001

# Update dnslib's QTYPE variable to allow SRV lookups.
QTYPE.forward[33] = "SRV"
QTYPE.reverse["SRV"] = 33

import dns.resolver, dns.message, dns.rdatatype, dns.opcode
import socket, struct, sys, signal

from optparse import OptionParser

from util import SRV, get_mdns_socket, TimeoutException

# Update dnslib's RDMAP to handle SRV records using our custom class.
RDMAP["SRV"] = SRV

# Multicast address for mDNS
MDNS_DESTINATION = '224.0.0.251'
MDNS_PORT = 5353

# Grab arguments from the user
usage = "Usage: mdns-lookup.py [options] hostname(s)"
argparser = OptionParser(usage = usage)
# argparser.add_option("-h", "--help", action="store_true", dest="usage")
argparser.add_option("-t", "--type", action="store", dest="type", default="A", help="Type for the mDNS lookup - eg, SRV")

(options, args) = argparser.parse_args()

if len(args) == 0:
    argparser.print_help()
    exit(1)

# Always use uppercase types
options.type = options.type.upper()

# Grab an mDNS socket ready for use
sock = get_mdns_socket()

# Create the DNS requests
for hostname in args:
    # Fix up the hostname if needed for the lookup.
    lookupHostname = hostname

    # Generate the DNS request.
    d = DNSRecord(DNSHeader(id = 0, bitmap = 0), q = DNSQuestion(lookupHostname, getattr(QTYPE, options.type), CLASS.IN))
    
    # Transmit.
    sock.sendto(d.pack(), (MDNS_DESTINATION, MDNS_PORT))
    
    # Timeout handler, just throws an exception.
    def timeout_handler(signum, frame):
        raise TimeoutException()

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5) # Time out after 5 seconds.
    
    # Handle incoming responses until we find ours, or time out.
    try:
        while True:
            buf, remote = sock.recvfrom(8192)
            
            d = DNSRecord.parse(buf)
            if (d.header.aa == 1) and (d.header.a > 0):
                # Check for a valid response to our request.
                success = False
                for response in d.rr:
                    if str(response.rname) == hostname:
                        success = True
                        
                        print "%s lookup for '%s' returned '%s'" % (options.type, hostname, str(response.rdata))
                        break
                
                if success:
                    break
    except TimeoutException:
        print "Timed out waiting for a response for '%s' (%s)" % (hostname, options.type)
    
    signal.signal(signal.SIGALRM, signal.SIG_DFL)

