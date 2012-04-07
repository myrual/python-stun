import socket
import sys, time

import signal, os
from impacket import ImpactPacket
from impacket import ImpactDecoder

class Spoofer:
    """Send a spoofed TCP packet
    USAGE: IP-destination port IP-source SYNno ACKno"""

    def __init__(self):
        pass

    #=================================================================
    def fakeConnection(self, argv, argc):
        
        dhost = argv[1]           # The remote host
        dport = int(argv[2])      # The same port as used by the server
        sport = dport             # The source port
        shost = argv[3]           # The source host

        if argc >= 5:
            SYN = int(argv[4])
        if argc == 6:
            ACK = int(argv[5])
            
        # Create a new IP packet and set its source and destination addresses.
        ip = ImpactPacket.IP()
        ip.set_ip_src(shost)
        ip.set_ip_dst(dhost)

        # Create a new TCP
        tcp = ImpactPacket.TCP()
        
        # Set the parameters for the connection
        tcp.set_th_sport(sport)
        tcp.set_th_dport(dport)
        tcp.set_th_seq(SYN)
        tcp.set_SYN()
        if argc == 6:
            tcp.set_th_ack(ACK)
            tcp.set_ACK()
        
        
        # Have the IP packet contain the TCP packet
        ip.contains(tcp)

        # Open a raw socket. Special permissions are usually required.
        protocol_num = socket.getprotobyname('tcp')
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol_num)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Calculate its checksum.
	tcp.calculate_checksum()
	tcp.auto_checksum = 1

        # Send it to the target host.
	self.s.sendto(ip.get_packet(), (dhost, dport))

        # Instantiate an IP packets decoder.
        # As all the packets include their IP header, that decoder only is enough.
##         decoder = ImpactDecoder.IPDecoder()

##         while 1:
##             packet = self.s.recvfrom(4096)[0]
##             # Packet received. Decode and display it.
##             packet = decoder.decode(packet)
##             print 'source:', packet.get_ip_src()
##             #print packet.get_ip_src(), packet.child().get_th_sport()
##             if isinstance(packet.child(),ImpactPacket.TCP)  and \
##                    packet.child().get_th_sport() > 50000:
##                 self._sniffed(packet)

    def _bind(self, shost):
        HOST = shost    # Symbolic name meaning the local host
        PORT = 50007              # Arbitrary non-privileged port
        self.stcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.stcp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.stcp.bind((HOST, PORT))
        
    def _sniffed(self, packet):
        print 'Packet sniffed'
        print packet
        print 'SYN:', packet.child().get_SYN()
        print 'SYNn:', packet.child().get_th_seq()
        print 'ACK:', packet.child().get_ACK()
        print 'ACKn:', packet.child().get_th_ack()

if __name__ == '__main__':
    p = Spoofer()
    p.fakeConnection(sys.argv, len(sys.argv))


