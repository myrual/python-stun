from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import p2pNetwork.testTCP.spoof as spoof
import p2pNetwork.testTCP.sniff as sniffer

class UDP_factory(DatagramProtocol):
  """An UDP service to allow a TCP connection:
   - Hole punching to connect in UDP to the other peer
   - Forces the ack number in a TCP response packet sent via UDP hole"""

  def __init__(self):
    self.sp = spoof.Spoofer()
    print 'Start to listen'
    reactor.listenUDP(9999, self)
    self.receivedSYN = 0
    self.sentSYN = 0
    
  
  def datagramReceived(self, data, (host, port)):
    """Listen for the peer's SYN
    If it has the SYN and the ACK send the TCP simulated response"""
    
    print "received %r from %s:%d\n" % (data, host, port)
    if data == "":
      return
    else:
      self.receivedSYN = 1
      self.ACK=int(data)+1
      self.fakeConnection()

  def punchHole(self):
    """To punch an hole in the NAT for UDP communication with the peer"""
    # Send void packet to punch an hole
    host = '10.193.167.86'
    port = 9999
    
    print "Punch hole..."
    self.transport.write("", (host, port))
    

  def send_SYN_to_ConnectionBroker(self, syn):
    """Sends the SYN number of my connect()ion to:
    - the other peer for TCP connction without spoofing
    - the connection broker for spoofing"""
    
    # Send SYN to connection broker via UDP protocol
    host = '10.193.167.86'
    port = 9999
    
    print "Send SYN to peer: "
    self.sentSYN = 1
    self.SYN=int(syn)
    #reactor.listenUDP(50007, self)
    #self.transport.write("%ld"%self.SYN, (host, port))
    #reactor.stop()
    self.fakeConnection()

  def fakeConnection(self):
    """Sends the SYNACK packet to the other peer
    Optional: sends a SYNACK to himself for a unidirectional
    simulated TCP connection"""
    
    print 'Fake connection:', self.sentSYN, self.receivedSYN, '\n'
    if self.sentSYN and self.receivedSYN:
      dhost = '10.193.167.86'
      dport = 50007
      shost = '10.193.161.57'
      sport = 50007
      argv = ('', dhost, '%d'%dport, shost, '%ld'%self.SYN, '%ld'%self.ACK)
      argc = len(argv)
      self.sp.fakeConnection(argv, argc)

      # -----------------------------------------
      # Auto send SYNACK
##       dhost = '10.193.161.57'
##       dport = 50007
##       shost = '10.193.167.86'
##       sport = 50007
##       self.SYN = self.ACK - 1
##       self.ACK = self.SYN + 1
##       argv = ('', dhost, '%d'%dport, shost, '%ld'%self.SYN, '%ld'%self.ACK)
##       argc = len(argv)
##       self.sp.fakeConnection(argv, argc)
      # -----------------------------------------

