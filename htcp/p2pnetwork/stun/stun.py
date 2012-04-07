# <copyright>
# Solipsis, a peer-to-peer serverless virtual world.
# Copyright (C) 2002-2005 France Telecom R&D
# 
# This software is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this software; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# </copyright>

import struct, socket, time, logging

from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log, failure
import ConfigParser


# This should be replaced with lookups of
# _stun._udp.divmod.com and _stun._udp.wirlab.net
DefaultServers = [
    ('stun.xten.net', 3478),
    ('sip.iptel.org', 3478),
    ('stun2.wirlab.net', 3478),
    ('stun.wirlab.net', 3478),
    ('stun1.vovida.org', 3478),
    ('tesla.divmod.net', 3478),
    ('erlang.divmod.net', 3478),
]

# The Message Types
StunTypes = {
   0x0001: "Binding Request",
   0x0101: "Binding Response",
   0x0111: "Binding Error Response",
   0x0002: "Shared Secret Request",
   0x0102: "Shared Secret Response",
   0x0112: "Shared Secret Error Response"
}

# The Message Attributes types
StunAttributes = {
   0x0001: 'MAPPED-ADDRESS',
   0x0002: 'RESPONSE-ADDRESS',
   0x0003: 'CHANGE-REQUEST',
   0x0004: 'SOURCE-ADDRESS',
   0x0005: 'CHANGED-ADDRESS',
   0x0006: 'USERNAME',
   0x0007: 'PASSWORD',
   0x0008: 'MESSAGE-INTEGRITY',
   0x0009: 'ERROR-CODE',
   0x000a: 'UNKNOWN-ATTRIBUTES',
   0x000b: 'REFLECTED-FROM',
}

# The Error Code
responseCodes = {
   400 : 'Bad Request',
   420 : 'Unknown attribute',
   431 : 'Integrity Check Failure',
   500 : 'Server Error',
   600 : 'Global Failure'
   }

import os
if os.path.exists('/dev/urandom'):
    def getRandomTID():
        return open('/dev/urandom').read(16)
else:
    def getRandomTID():
        # It's not necessary to have a particularly strong TID here
        import random
        tid = [ chr(random.randint(0,255)) for x in range(16) ]
        tid = ''.join(tid)
        return tid

# ============================================================================
# The STUN protocol client/server methods
# ============================================================================
class StunProtocol(DatagramProtocol, object):

    def __init__(self, servers=DefaultServers, *args, **kwargs):
        self._pending = {}
        self.servers = servers
        super(StunProtocol, self).__init__(*args, **kwargs)
        
        # Initialise the variable
        avtypeList = {}
        mt, pktlen, tid = (0, 0, '0')
        toAddr = ('0.0.0.0', 0)
    
    def datagramReceived(self, dgram, address):
        """Called when a message is arrived"""
        try:
            self.stopTimeout()
        except:
            pass
            
        print 'Received message from:' , address
        self.parseMessage(dgram)
        self.analyseMessage(address)

    def parseMessage(self, dgram):
        """Parse the message received"""
        self.avtypeList = {}
        # Header
        self.mt, self.pktlen, self.tid = struct.unpack('!hh16s', dgram[:20])
        # Payload
        remainder = dgram[20:]
        while remainder:
            avtype, avlen = struct.unpack('!hh', remainder[:4])
            val = remainder[4:4+avlen]
            avtype = StunAttributes.get(avtype, 'Unknown type:%04x'%avtype)
            self.avtypeList[avtype] = val
            remainder = remainder[4+avlen:] 
    
    def send(self, to, avpairs=()):
        """Pack the response and send it to the client"""

        self.toAddr = to
        avstr = ''
        # add any attributes in Payload
        for a,v in avpairs:
            if a == 0x0001 or a == 0x0002 or a == 0x0004 \
                   or a == 0x0005 or a == 0x000b:
                avstr = avstr + struct.pack( \
                    '!hhccH4s', a, len(v), '0', '%d' % 0x01, int(v[:4]), v[4:])
                
            elif a == 0x0003 or a == 0x0000:
                avstr = avstr + struct.pack('!hhi', a, 4, int(v))
                
            elif a == 0x0009:
                err_class = int(v[0])
                number = int(v) - err_class*100
                phrase = responseCodes[int(v)]
                avstr = avstr + struct.pack( \
                    '!hhi%ds' % len(phrase), a, 4 + len(phrase), \
                    (err_class<<8) + number, phrase)
                
            elif a == 0x000a:
                avstr = avstr + struct.pack('!hh', a, len(v)*2)
                for unkAttr in v:
                    avstr = avstr + struct.pack('!h', unkAttr)
            
        pktlen = len(avstr)
        if pktlen > 65535:
            raise ValueError, "stun request too big (%d bytes)" % pktlen
        # Add header and send
        self.pkt = struct.pack('!hh16s', self.mt, pktlen, self.tid) + avstr
        #print 'Send to:', self.toAddr
        self.transport.write(self.pkt, self.toAddr)

    def sendPack(self):
        """Send pack: used in retrasmission"""
        self.transport.write(self.pkt, self.toAddr)

    def blatServers(self):
        for s in self.servers:
            self.sendRequest(s)     

    def gotMappedAddress(self, addr, port):
        """When the procedure has discovered the network configuration"""
        
        logging.info("got address %s %s (should I have been overridden?)" \
                     % (addr, port))


# ------- Implemented in server/client ----------
    def stopTimeout(self):
        pass

    def analyseMessage(self):
        pass

    def checkMessage(self):
        pass

    def Stop(self):
        """ Stop listening. """
        pass

    
#=============================================================================
#   STUN Server
# ============================================================================
class StunServer(StunProtocol, object):
    """ The code for the server """
    
    # Load configuration
    config = ConfigParser.ConfigParser()
    config.read("p2pNetwork.conf")
    #config = ConfigData('p2pNetwork.p2pNetwork.conf')
##     myAddress      = (socket.gethostbyname(socket.gethostname()), \
##                       int(config.get('stun', 'stunPort')))
##     myOtherAddress = (socket.gethostbyname(socket.gethostname()), \
##                       int(config.get('stun', 'otherStunPort')))
    myAddress      = ('127.0.0.1', int(config.get('stun', 'stunPort')))
    myOtherAddress = ('127.0.0.1', int(config.get('stun', 'otherStunPort')))
    _otherStunServer = config.get('stun', 'otherStunServer').split(':')
    otherStunServer = (_otherStunServer[0], int(_otherStunServer[1]))
    _otherStunServer = config.get('stun', 'otherStunServerPort').split(':')
    otherStunServerPort = (_otherStunServer[0], int(_otherStunServer[1]))
    

##     myAddress = (socket.gethostbyname(socket.gethostname()), 3478)
##     myOtherAddress = (socket.gethostbyname(socket.gethostname()), 3479)
##     otherRdvServer = ('127.0.0.1', 3478)
##     otherRdvServerPort = ('127.0.0.1', 3479)

    def analyseMessage(self, fromAddr):
        """Analyse the message received"""
        
        self.responseType = 'Binding Response'
        listAttr = ()
        listUnkAttr = ()
        toAddr = fromAddr # reply to ...
        numUnkAttr = 0 # Number of unknown attributes

        
        if self.mt == 0x0001:
            # -------------------------------------------------------------
            # if binding request
            logging.info("got STUN request from %s" % repr(fromAddr))
            # response
            for avtype in self.avtypeList:
                # For all correct attributes 
                if avtype == 'RESPONSE-ADDRESS':
                    # Send the response to the address in RESPONSE-ADDRESS
                    # and add REFLECTED-FROM attribute
                    dummy,family,port,addr = struct.unpack('!ccH4s', self.avtypeList[avtype])
                    toAddr = (socket.inet_ntoa(addr), port)
                    listAttr = listAttr + ((0x000b, self.getPortIpList(self.myAddress)),)
                    self.responseType = "Binding Response"
                elif avtype == 'CHANGE-REQUEST':
                    change = (struct.unpack('!i', self.avtypeList[avtype]))[0]
                    if change == 2:
                        # change the source Port --> send from/to the other port
                        # TODO: change reactor
                        toAddr = self.myOtherAddress
                         # RESPONSE-ADDRESS
                        listAttr = listAttr + ((0x0002, self.getPortIpList(fromAddr)),) 
                        self.responseType = "Binding Request"
                    elif change == 4:
                        # change the source IP --> send from/to the other server
                        toAddr = self.otherStunServer
                         # RESPONSE-ADDRESS
                        listAttr = listAttr + ((0x0002, self.getPortIpList(fromAddr)),)
                        self.responseType = "Binding Request"
                    elif change == 6:
                        # change the source IP/Port --> send from/to the other server
                        toAddr = self.otherStunServerPort
                        #toAddr = self.myAddress
                         # RESPONSE-ADDRESS
                        listAttr = listAttr + ((0x0002, self.getPortIpList(fromAddr)),)
                        self.responseType = "Binding Request"
                elif avtype[:12] == 'Unknown type':
                    listAttr = listAttr + ((0x0009, '420'),) # ERROR-CODE
                    unkAttr = int(avtype[13:])
                    listUnkAttr = listUnkAttr + (unkAttr,)
                    numUnkAttr+=1
                    self.responseType = "Binding Error Response"

            # To respect that the total length of the list is a multiple of 4 bytes
            if numUnkAttr%2 != 0:
                listUnkAttr = listUnkAttr + (unkAttr,)
            if listUnkAttr != ():
                listAttr = listAttr + ((0x000a, listUnkAttr),)
                        
            self.createResponse(toAddr, listAttr)
        else:
            # -------------------------------------------------------------
            # Other not implemented request
            listAttr = listAttr + ((0x0009, '400'),) # ERROR-CODE
            self.responseType = "Binding Error Response"
            self.createResponse(toAddr, listAttr)
            logging.error("STUN not implemented")

    def createResponse(self, toAddr, listAttr):
        """Pack the response and send it to the client"""
        avpairs = ()
        if self.responseType == "Binding Response":
            self.mt = 0x0101 # binding response
            # MAPPED-ADDRESS # SOURCE-ADDRESS # CHANGED-ADDRESS
            avpairs = avpairs + ((0x0001, self.getPortIpList(toAddr)),) 
            avpairs = avpairs + ((0x0004, self.getPortIpList(self.myAddress)),) 
            avpairs = avpairs + ((0x0005, self.getPortIpList(self.otherStunServer)),) 
        elif self.responseType == "Binding Request":
            self.mt = 0x0001 # binding request (to other  rdv server)
        elif self.responseType == "Binding Error Response":
            self.mt = 0x0111 # binding error response

        avpairs = avpairs + listAttr    
        self.send(toAddr, avpairs)

    def getPortIpList(self, address):
        a, b, c, d = address[0].split('.')
        return '%d%c%c%c%c' % (address[1], int(a), int(b), int(c), int(d))

#=============================================================================
#   STUN Client
# ============================================================================
class StunClient(StunProtocol, object):

    # A structure to save the client network configuration
    configurationText = ['NAT presence      ', \
                         'NAT type          ', \
                         'My private address', \
                         'My public address ', \
                         'Informations      ']    
    
    configuration     = ['unknown', \
                         'unknown', \
                         'unknown:unknown', \
                         'unknown:unknown',\
                         '...']
    # Initial timeout valor
    stun_timeout = 0.1
 
    # For the tests like in rfc 3489
    test = 1
    addressMatch     = 1
    oldMappedAddress = ''
    
    def stopTimeout(self):
        """Stops the active timeout"""
        self.timeout.cancel()
        # Reinitialise variables
        self.stun_timeout = 0.1
        self.request = 1
        
    def analyseMessage(self, address):
        """
        Analyse the server's response
        """
        
        listAttr = ()
##         self.configuration[2] = (socket.gethostbyname(socket.gethostname()), \
##                                  self.listenPort)
        self.configuration[2] = ('127.0.0.1', self.listenPort)
        
        # Check tid is one we sent and haven't had a reply to yet
        if self._pending.has_key(self.tid):
            del self._pending[self.tid]
        else:
            logging.error("Error, unknown transaction ID %s, have %r" \
                          % (self.tid, self._pending.keys()))
            return
  
        if self.mt == 0x0101:
            # -------------------------------------------------------------
            # binding response
            
            dummy,family,port,addr = struct.unpack( \
                '!ccH4s', self.avtypeList["MAPPED-ADDRESS"])
            mappedAddress = (socket.inet_ntoa(addr), port)
            
            if self.test == 1:
                # ********************************************************
                # If it's in the first test (see rfc3489)
                
                if self.addressMatch:
                    # It's the first test 1
                    if mappedAddress[0] == self.configuration[2][0] :
                        print ' >> test 1 (first time): address match'
                        self.addressMatch = 1
                        # No NAT !!!
                        self.configuration[0] = "none"
                        self.configuration[1] = "none"
                        
                        # It does test 2
                        print "    # Start test 2"
                        self.test = 2
                        listAttr = listAttr + ((0x0003, 6),) # CHANGE-REQUEST
                        self.sendRequest(address, listAttr)
                        return
                    else :
                        print(' >> test 1 (first time): address does not match')
                        self.addressMatch = 0
                        # Behind a NAT !!!
                        self.configuration[0] = "Yes"
                        # It does test 2
                        print("    # Start test 2")
                        self.test = 2
                        listAttr = listAttr + ((0x0003, 6),) # CHANGE-REQUEST
                        self.sendRequest(address, listAttr)
                        return
                else:
                    # It's the second time test 1
                    if self.oldMappedAddress != mappedAddress:
                        # Symmetric NAT --> exit
                        print ' >> test 1 (second time): address does not match'
                        self.configuration[1] = 'Symmetric'
                        self.configuration[3] = mappedAddress
                        self.gotMappedAddress(socket.inet_ntoa(addr),port)
                        return
                    else:
                        # Either behind a restricted or port restricted NAT
                        # It does test 3
                        print ' >> test 1 (second time): address match'
                        print("    # Start test 3")
                        self.configuration[3] = self.oldMappedAddress
                        self.test = 3
                        listAttr = listAttr + ((0x0003, 2),) # CHANGE-REQUEST
                        self.sendRequest(address, listAttr)
                        return
                
            elif  self.test == 2:
                # ********************************************************
                # If it's in the second test (see rfc3489)
                
                if self.addressMatch:
                    # Open access to internet
                    print(' >> test 2: address matched ')
                    self.configuration[3] = self.configuration[2]
                    self.configuration[4] = "Open access to internet"
                    self.gotMappedAddress(socket.inet_ntoa(addr),port)
                    return
                else:
                    #Full cone NAT
                    print(' >> test 2: address did not match ')
                    self.configuration[1] = "Full cone"
                    self.configuration[3] = mappedAddress
                    self.gotMappedAddress(socket.inet_ntoa(addr),port)
                    return
            
            elif  self.test == 3:
                # ********************************************************
                # If it's in the third test (see rfc3489)
                
                # Restricted NAT
                self.configuration[1] = "Restricted cone"
                self.configuration[3] = mappedAddress[0], 'unknown'
                self.gotMappedAddress(socket.inet_ntoa(addr),port)
                return 
            
            return
        
        elif self.mt == 0x0111:
            # -------------------------------------------------------------
            # Binding Error Response
            logging.error("STUN got an error response:")
            # Extract the class and number
            error, phrase = self.getErrorCode()
            if error == 420:
                _listUnkAttr = self.getListUnkAttr()
                logging.error((error, phrase, _listUnkAttr))
            else:
                logging.error((error, phrase))               
        else:
            logging.error("STUN got unknown message")

    def sendRequest(self, server, avpairs=()):
        """Send the initial request
        to discover network configuration"""
        
        self.tid = getRandomTID()
        self.mt = 0x0001 # binding request
        self._pending[self.tid] = (time.time(), server)
        self.stun_timeout = 0.1
        self.request = 1
        self.server = server
        # Start timeout and send message
        self.timeout = reactor.callLater(self.stun_timeout, self._timeout)
        self.send(self.server, avpairs)

    def _timeout(self):
        """If a timeout is expired
        Send 9 message at:
           0ms, 100ms, 300ms, 700ms, 1500ms, 3100ms, 4700ms, 6300ms, 7900ms
        """
        self.request += 1
        if self.request == 10:
            self.retransmissionEnded()
            return
        if self.stun_timeout < 1.6:
            self.stun_timeout = 2 * self.stun_timeout
        # Re-send message
        self.timeout = reactor.callLater(self.stun_timeout, self._timeout)        
        self.sendPack()
        
    def retransmissionEnded(self):
        """Transaction have failed (called at 9500ms)"""

        self.stun_timeout = 0.1
        self.request = 1
        
        if self.test == 1:
            # ********************************************************
            # If it's in the first test (see rfc3489)
            # UDP blocked --> exit
            print ' >> test 1 (first time)(timeout): UDP blocked'
            self.configuration[4] = 'UDP blocked'
            self.deferred.errback(failure.DefaultException("UDP blocked"))
            return

        elif  self.test == 2:
            # ********************************************************
            # If it's in the second test (see rfc3489)
            if self.addressMatch:
                # Symmetric UDP Firewall --> exit
                print ' >> test 2 (timeout): Symmetric UDP Firewall'
                self.configuration[4] = 'Symmetric UDP Firewall'
                self.gotMappedAddress(self.configuration[2])
                return
            else:
                # Start Test 1 (second time)
                print ' >> test 2 (timeout)'
                print "    # Start test 1 (second time)"
                dummy,family,port,addr = struct.unpack( \
                    '!ccH4s', self.avtypeList["MAPPED-ADDRESS"])
                mappedAddress = (socket.inet_ntoa(addr), port)
                self.oldMappedAddress = mappedAddress
                self.test = 1
                dummy,family,port,addr = struct.unpack( \
                    '!ccH4s', self.avtypeList["CHANGED-ADDRESS"])
                server = (socket.inet_ntoa(addr), port)
                self.sendRequest(server)
                return
            
        # If it's in the third test (see rfc3489)
        elif  self.test == 3:
            # Port restricted
            print ' >> test 3 (timeout): Port Restricted cone'
            self.configuration[1] = "Port Restricted cone"
            self.gotMappedAddress(self.configuration[3])
            return

        return

    def getErrorCode(self):
        """If an error occurred: return the error code"""
        
        # Extract the class and number
        error, phrase = struct.unpack('!i%ds' % (len(self.avtypeList["ERROR-CODE"])-4), \
                                      self.avtypeList["ERROR-CODE"])
        number = error - ((error>>8)<<8)
        err_class = ((error - number)>>8)*100
        return err_class + number, phrase

    def getListUnkAttr(self):
        """Return the list of Unknown attributes"""
        
        _listUnkAttr = ()
        listUnkAttr = struct.unpack( \
            '!%dh' % int(len(self.avtypeList["UNKNOWN-ATTRIBUTES"])/2), \
            self.avtypeList["UNKNOWN-ATTRIBUTES"])
        for attr in listUnkAttr:
            _listUnkAttr = _listUnkAttr + ('0x%04x'%attr,)
        return _listUnkAttr
    
    def printConfiguration(self):
        """ Print the client's network configuration """

        print "\n*---------------------------------------------------------------*"
        print "Configuration:\n"
        for i in range(0,5):
            print "\t", self.configurationText[i], "\t", self.configuration[i]
        print "*---------------------------------------------------------------*"

    def getConfiguration(self):
        """Gets a list with the network configuration:
        (NAT presence, NAT type, private address, public address)"""
        return self.configuration
        
    def getNATType(self):
        """Returns the NAT's type"""
        return self.configuration[1]
        
    def getPrivateAddress(self):
        """Retruns the client's private address"""
        return self.configuration[2]
        
    def getPublicAddress(self):
        """Retruns the client's public address"""
        return self.configuration[3]
