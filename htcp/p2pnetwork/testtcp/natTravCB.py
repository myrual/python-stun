# Echo server program
import socket
import sys, time
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import threads
import twisted.internet.defer as defer

import signal, os
import random
import p2pNetwork.testTCP.sniffer as sniffer
from impacket import ImpactPacket


class ConnectionBroker(DatagramProtocol):
    """Listen on UDP port for the two SYNs from peers"""

    def __init__(self):
        self.t = [0, 0]
        #self.t[1] = (('10.193.161.57', 50007), random.randint(0, 9999) )
        self.msg_from_peer = 0
    
    def datagramReceived(self, data, addr):
        print "received %r from:" % (data), addr
        self.msg_from_peer += 1
        self.t[self.msg_from_peer-1] = (addr, int(data))
        
        if self.msg_from_peer == 2:
            self.msg_from_peer = 0
            b = Broker()
            b.fakeConnection(self.t)

    


class Broker(Protocol):
    """Broke the NAT firewall sending spoofed packet"""

    def __init__(self):

        # Start to sniff packets
        # run method in thread and get result as defer.Deferred
        #reactor.callInThread(sniffer.sniff, self)
        pass

    #=================================================================
    def fakeConnection(self, table):

        for i in (0, 1):
            port = 50007
            dhost = table[i][0][0]    # The remote host
            shost = table[(i+1)%2][0][0]    # The source host
            dport = port              # The same port as used by the server
            sport = dport             # The source port
            
            SYN = table[(i+1)%2][1]
            ACK = table[i][1]+1
                
            # Create a new IP packet and set its source and destination addresses.
            ip = ImpactPacket.IP()
            print 'IPs:', shost, dhost
            ip.set_ip_src(shost)
            ip.set_ip_dst(dhost)
            
            # Create a new TCP
            tcp = ImpactPacket.TCP()
            
            # Set the parameters for the connection
            print 'Ports:', sport, dport
            tcp.set_th_sport(sport)
            tcp.set_th_dport(dport)
            print 'SYN-ACK:', SYN, ACK
            tcp.set_th_seq(SYN)
            tcp.set_SYN()
            tcp.set_th_ack(ACK)
            tcp.set_ACK()
        
        
            # Have the IP packet contain the TCP packet
            ip.contains(tcp)
            
            # Open a raw socket. Special permissions are usually required.
            protocol_num = socket.getprotobyname('tcp')
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol_num)
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            #self._bind()

            # Calculate its checksum.
            tcp.calculate_checksum()
            tcp.auto_checksum = 1

            # Send it to the target host.
            self.s.sendto(ip.get_packet(), (dhost, dport))

    def connection(self):
        """DEPRECATED"""
        RHOST = '10.193.161.93'    # The remote host
        RPORT = 50007              # The same port as used by the server

        self._bind()
        
        # Start timeout and try to connect
        print 'Try to connect...'
        time.sleep(1)
        self.s.connect((RHOST, RPORT))
        print 'connection made'

    def _sniffed(self, packet):
        """Print infos on sniffed packet"""
        
        print 'Packet sniffed'
        print packet
        print 'SYNn:', packet.child().get_th_seq()
        print 'SYN:', packet.child().get_SYN()
        print 'ACK:', packet.child().get_ACK()
        print 'ACKn:', packet.child().get_th_ack()

## if __name__ == '__main__':
##     b = Broker()
##     b.fakeConnection(sys.argv, len(sys.argv))

reactor.listenUDP(9999, ConnectionBroker())
reactor.run()  
