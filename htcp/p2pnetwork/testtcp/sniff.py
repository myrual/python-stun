#!/usr/bin/env python2

import sys
import pcap
import string
import time
import socket
import struct

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import p2pNetwork.testTCP.spoof as spoof

protocols={socket.IPPROTO_TCP:'tcp',
           socket.IPPROTO_UDP:'udp',
           socket.IPPROTO_ICMP:'icmp'}

def decode_ip_packet(s):
  d={}
  d['version']=(ord(s[0]) & 0xf0) >> 4
  d['header_len']=ord(s[0]) & 0x0f
  d['tos']=ord(s[1])
  d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
  d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
  d['flags']=(ord(s[6]) & 0xe0) >> 5
  d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
  d['ttl']=ord(s[8])
  d['protocol']=ord(s[9])
  d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
  #d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
  #d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
  d['source_address']='?'
  d['destination_address']='?'
  if d['header_len']>5:
    d['options']=s[20:4*(d['header_len']-5)]
  else:
    d['options']=None
  d['data']=s[4*d['header_len']:]
  decode_tcp_packet(d['data'], d)
  return d

def decode_tcp_packet(s, d):
  d['synno']=struct.unpack('!L', s[4:8])[0]
  d['ackno']=struct.unpack('!L', s[8:12])[0]
  

def dumphex(s):
  bytes = map(lambda x: '%.2x' % x, map(ord, s))
  for i in xrange(0,len(bytes)/16):
    print '    %s' % string.join(bytes[i*16:(i+1)*16],' ')
  print '    %s' % string.join(bytes[(i+1)*16:],' ')
    

def print_packet(timestamp, data, arg=''):
  if not data:
    return

  if data[12:14]=='\x08\x00':
    decoded=decode_ip_packet(data[14:])
    print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                           time.localtime(timestamp)),
                             timestamp % 60,
                             decoded['source_address'],
                             decoded['destination_address'])
    for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                'flags', 'fragment_offset', 'ttl']:
      print '  %s: %d' % (key, decoded[key])
    print '  protocol: %s' % protocols[decoded['protocol']]
    print '  header checksum: %d' % decoded['checksum']
    print '  data:'
    dumphex(decoded['data'])
    print '  SYNno:', decoded['synno']
    print '  ACKno:', decoded['ackno']




      
#if __name__=='__main__':
def sniff(argv, udp_obj):
  """Sniff packets using pcap libriry
  and call the method to send the SYN nomber to hte peer
  or to Connection Broker"""
 
  sys.argv = argv
  if len(sys.argv) < 3:
    print 'usage: sniff.py <interface> <expr>'
    sys.exit(0)
    
  dev = sys.argv[1]
  #p = pcap.pcap(dev)
  p = pcap.pcapObject()
  #dev = pcap.lookupdev()
  net, mask = pcap.lookupnet(dev)
  # note:  to_ms does nothing on linux
  p.open_live(dev, 1600, 0, 100)
  #p.dump_open('dumpfile')
  p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

  # try-except block to catch keyboard interrupt.  Failure to shut
  # down cleanly can result in the interface not being taken out of promisc.
  # mode
  #p.setnonblock(1)
  #udp_obj = UDP_factory()
  #reactor.run()
  udp_obj.punchHole()
  try:
    while 1:
    #for ts, pkt in p:
    #for i in range(1,9):
      #print i
      #print_packet(ts, pkt)
      #p.dispatch(print_packet, -1)
      p.dispatch(1, udp_obj.send_SYN_to_ConnectionBroker)
      #p.loop(1, udp_obj.send_SYN_to_ConnectionBroker)
      
      #udp_obj.send_SYN_to_ConnectionBroker(ts, pkt)
      #break
      print 'break'
      break
    # specify 'None' to dump to dumpfile, assuming you have called
    # the dump_open method
    #  p.dispatch(0, None)

    # the loop method is another way of doing things
    #  p.loop(1, print_packet)

    # as is the next() method
    # p.next() returns a (pktlen, data, timestamp) tuple 
    #  apply(print_packet,p.next())
  except KeyboardInterrupt:
    print '%s' % sys.exc_type
    print 'shutting down'
    print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
  

