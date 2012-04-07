from twisted.internet.protocol import Protocol, ClientFactory, Factory
from twisted.internet import reactor
from twisted.internet import threads
from sys import stdout, stdin

import sys
import socket
import time

import p2pNetwork.testTCP.sniffy as sniffer
import p2pNetwork.testTCP.udpSniffer as udp_sniffer

class Echo(Protocol):
    """A test for TCP connection:
    - a normal TCP connection
    - with a thread to simulate the simultaneous TCP initiation"""
        
    def dataReceived(self, data = ''):
        stdout.write(data)

    def connectionMade(self):
        print 'Connection Made!!!'
        
        data=stdin.readline()
        while data != 'exit\n':
            self.transport.write(data)
            data=stdin.readline()
        self.transport.loseConnection()    

class EchoClientFactory(ClientFactory):

    
    def startedConnecting(self, connector):
        print 'Started to connect.'
        self.e = Echo()
    
    def buildProtocol(self, addr):
        print 'Connected.'
        return self.e
    
    def clientConnectionLost(self, connector, reason):
        print 'Lost connection.  Reason:', reason
        reactor.stop()
    
    def clientConnectionFailed(self, connector, reason):
        print 'Connection failed. Reason:', reason
        reactor.stop()

# Start to listen for UDP connection
#reactor.listenUDP(9999, udp_sniffer.UDP_factory())
udp_obj = udp_sniffer.UDP_factory()

# Start to sniff packets (run method in thread)
argv = ('', 'eth0', 'tcp port 50007')
sniffer.sniff(argv, udp_obj)

# Wait a little bit...
time.sleep(2)

# Start TCP connection
print 'Start TCP connection'
reactor.connectTCP('10.193.167.86', 50007, EchoClientFactory(), 30, ('192.168.1.109', 50007))
reactor.run()
