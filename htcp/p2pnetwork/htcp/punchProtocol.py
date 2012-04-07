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
from twisted.internet.protocol import Protocol
from twisted.python import log, failure

#
# This is a list of allowed arguments in the "Hole Punching" protocol.

# The Message Types
PunchTypes = {0x1001 : 'Lookup Request',          \
              0x1101 : 'Lookup Response', \
              0x1111 : 'Connection Request',             \
              0x1002 : 'Registration Request',           \
              0x1003 : 'Registration Response',           \
              0x1102 : 'Connection to peer',             \
              0x1112 : 'Error Response'}

# The Message Attributes types
PunchAttributes = { 0x0001 : 'USER-ID',             \
                    0x0002 : 'PUBLIC-ADDRESSE',           \
                    0x0003 : 'PRIVATE-ADDRESSE',          \
                    0x0004 : 'NAT-TYPE' ,           \
                    0x0005 : 'REQUESTOR-PUBLIC-ADDRESSE', \
                    0x0006 : 'REQUESTOR-PRIVATE-ADDRESSE',\
                    0x0007 : 'REQUESTOR-NAT-TYPE',  \
                    0x0008 : 'ERROR-CODE',          \
                    0x0009 : 'UNKNOWN-ATTRIBUTES'   }

# The Error Code
ResponseCodes = {
   400 : 'Bad Request',
   420 : 'Unknown attribute',
   431 : 'Integrity Check Failure',
   500 : 'Server Error',
   600 : 'Global Failure'
   }

DefaultServers = [
    ('localhost', 6060),
]

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
# The Hole Punching protocol client/server methods
# ============================================================================
class PunchProtocol(DatagramProtocol, Protocol, object):
    """
    This class parses and builds hole punching messages.
    """
    
    avtypeList = {}
    mt, pktlen, tid = (0, 0, '0')
    toAddr = ('0.0.0.0', 0)

    # The ID table with:  | id (=primary key) | public IP (= foreign key)| 
    peersIDTab = {}     
    # The IP table with: | public IP (=primary key)| private IP | NAT type | 
    peersIPTab = {}

    def __init__(self, *args, **kwargs):
        # Initialize the variables
        self._pending = {}
        super(PunchProtocol, self).__init__(*args, **kwargs)
        self.TCPsessionStarted = 0
        print 'TCP:', self.TCPsessionStarted
            
    def datagramReceived(self, dgram, address):
        """Called when a message is arrived"""
        self.stopTimeout()
        print 'Received message from:' , address
        self.parseMessage(dgram)
        self.analyseMessage(address)

    def dataReceived(self, data):
        print 'dataReceived'
        stdout.write(data)

    def startedConnecting(self, connector):
        print 'Started to connect.'

    def clientConnectionFailed(self, connector, reason):
        print 'Connection failed. Reason:', reason
    
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
            avtype = PunchAttributes.get(avtype, 'Unknown type:%04x'%avtype)
            self.avtypeList[avtype] = val
            remainder = remainder[4+avlen:]
 
    def createMessage(self, toAddr, listAttr):
        """Pack the response and send it to the client"""
        avpairs = ()
        if self.responseType == "Lookup Request":
            self.mt = 0x1001 # Lookup Request
        elif self.responseType == "Lookup Response":
            self.mt = 0x1101 # Lookup Response
        elif self.responseType == "Connection Request":
            self.mt = 0x1111 # Connection Request 
        elif self.responseType == "Registration Request":
            self.mt = 0x1002 # Registration Request
        elif self.responseType == "Registration Response":
            self.mt = 0x1003 # Registration Response
        elif self.responseType == "Connection to peer":
            self.mt = 0x1102 # Connection to peer
        elif self.responseType == "Error Response":
            self.mt = 0x1112 # Error Response
        avpairs = avpairs + listAttr
##         self.send(toAddr, avpairs)
        
##     def send(self, toAddr, avpairs=()):
##         """Pack the response and send it"""

        self.toAddr = toAddr
        avstr = ''
        # add any attributes in Payload
        for a,v in avpairs:
            if a == 0x0001:
                flength = len(v)
                if flength%4 != 0:
                    flength = 4 - len(v)%4 + len(v)
                    v = v.zfill(flength)
                avstr = avstr + struct.pack( \
                    '!hh%ds'%flength, a, len(v), v)
            elif a == 0x0002 or a == 0x0003 or a == 0x0005 or a == 0x0006:
                avstr = avstr + struct.pack( \
                    '!hhccH4s', a, len(v), '0', '%d' % 0x01, int(v[:4]), v[4:])
            elif a == 0x0004 or a == 0x0006:
                pass
            elif a == 0x0008:
                err_class = int(v[0])
                number = int(v) - err_class*100
                phrase = responseCodes[int(v)]
                avstr = avstr + struct.pack( \
                    '!hhi%ds' % len(phrase), a, 4 + len(phrase), \
                    (err_class<<8) + number, phrase)
            elif a == 0x0009:
                avstr = avstr + struct.pack('!hh', a, len(v)*2)
                for unkAttr in v:
                    avstr = avstr + struct.pack('!h', unkAttr)
            
        pktlen = len(avstr)
        if pktlen > 65535:
            raise ValueError, "stun request too big (%d bytes)" % pktlen
        # Add header and send
        self.pkt = struct.pack('!hh16s', self.mt, pktlen, self.tid) + avstr

        if self.TCPsessionStarted:
            pass
        else:
            self.transport.write(self.pkt, self.toAddr)

    def sendPack(self):
        """Send pack: used in retrasmission"""
        self.transport.write(self.pkt, self.toAddr)

    def getPortIpList(self, address):
        """Return a well formatted string with the address"""
        return '%d%s' % (address[1], socket.inet_aton(address[0]))

    def setServer(self, server):
        """Sets the Rendezvous server address"""
        self.server = server

    def setTransport(self, transport):
        """Set the transport object to send message on network"""
        self.transport = transport

    def stopTimeout(self):
        pass

    
#=============================================================================
#  Connection Broker for Hole Punching Protocol
# ============================================================================
class ConnectionBroker(PunchProtocol, object):
    """ The code for the server """

    # TODO: read conf from file
##     myAddress = (socket.gethostbyname(socket.gethostname()), 3478)
##     myOtherAddress = (socket.gethostbyname(socket.gethostname()), 3479)
    myAddress = ('127.0.0.1', 3478)
    myOtherAddress = ('127.0.0.1', 3479)
    otherRdvServer = ('127.0.0.1', 3478)


    def analyseMessage(self, fromAddr):
        """Analyse the message received"""
        
        self.responseType = 'Binding Response'
        listAttr = ()
        listUnkAttr = ()
        toAddr = fromAddr # reply to ...
        numUnkAttr = 0 # Number of unknown attributes

        
        if self.mt == 0x1001:
            # -------------------------------------------------------------
            # if Lookup Request

            print "Lookup Request"
            
            #TODO
            #if checkUnkAttributes(...):
            #    return
            logging.info("got PUNCH request from %s" % repr(fromAddr))
            #**************************************************************
            # Reply to requestor
            toAddr = fromAddr
            if not ('USER-ID' in self.avtypeList):
                dummy,family,port,ip = struct.unpack( \
                    '!ccH4s', self.avtypeList['PUBLIC-ADDRESSE'])
                addr = (socket.inet_ntoa(ip), port)
                key = addr
            else:
                key = self.avtypeList['USER-ID']

            # Load the peer configuration
            peerInfo = self.getPeerInfo(key)
            print "--", peerInfo, "--"
            if peerInfo == ():
                # TODO: contact other connection broker
                # TODO: send error to client
                return
            if peerInfo[0] != '':
                listAttr = listAttr + ((0x0001, peerInfo[0]),)

            listAttr = listAttr + ((0x0002, self.getPortIpList(peerInfo[1])),)
            listAttr = listAttr + ((0x0003, self.getPortIpList(peerInfo[2])),)
            # TODO: add NAT type (?)
            #listAttr = listAttr + ((0x0004, peerInfo[4]),)
            
            self.responseType = "Lookup Response"    
            self.createMessage(toAddr, listAttr)

            #**************************************************************
            # Advise peer
            toAddr = peerInfo[1] # the peer's address
            if 'REQUESTOR-PUBLIC-ADDRESSE' in self.avtypeList:
                dummy,family,port,ip = struct.unpack( \
                    '!ccH4s', self.avtypeList['REQUESTOR-PUBLIC-ADDRESSE'])
                addr = (socket.inet_ntoa(ip), port)
            listAttr = listAttr + ((0x0005, self.getPortIpList(addr)),)

            if 'REQUESTOR-PRIVATE-ADDRESSE' in self.avtypeList:
                dummy,family,port,ip = struct.unpack( \
                    '!ccH4s', self.avtypeList['REQUESTOR-PRIVATE-ADDRESSE'])
                addr = (socket.inet_ntoa(ip), port)
            listAttr = listAttr + ((0x0006, self.getPortIpList(addr)),)
            # TODO: add NAT type (?)
            #listAttr = listAttr + ((0x0007, listConf[4]),)
            
            self.responseType = "Connection Request"   
            self.createMessage(toAddr, listAttr)
            
        elif self.mt == 0x1002:
            # -------------------------------------------------------------
            # Registration Request
            
            #TODO
            #if checkUnkAttributes(...):
            #    return
            URI = self.avtypeList['USER-ID']
            publAddr = fromAddr
##             dummy,family,port,ip = struct.unpack( \
##                 '!ccH4s', self.avtypeList['PUBLIC-ADDRESSE'])
##             publAddr = (socket.inet_ntoa(ip), port)
            dummy,family,port,ip = struct.unpack( \
                '!ccH4s', self.avtypeList['PRIVATE-ADDRESSE'])
            privAddr = (socket.inet_ntoa(ip), port)
            # TODO: add id and NAT type
            peerInfo = (URI, publAddr, privAddr, '')
            self.registrePeer(peerInfo)
            self.printActiveConnection()
            
            # TODO: send ok response to Registration Requestor
            listAttr = listAttr + ((0x0002, self.getPortIpList(publAddr)),)
            listAttr = listAttr + ((0x0003, self.getPortIpList(privAddr)),)
            self.responseType = 'Registration Response'
            self.createMessage(toAddr, listAttr)

        else:
            # -------------------------------------------------------------
            # Bad Request
            listAttr = listAttr + ((0x0009, '400'),) # ERROR-CODE
            self.responseType = "Error Response"
            self.createResponse(toAddr, listAttr)
            logging.error("Punch error")


    def checkUnkAttributes(self,):
        """Check if there is some unknown attributes in request message"""
        
        listAttr = ()
        listUnkAttr = ()
        # For unknown attributes in request message
        for avtype in self.avtypeList:
            if avtype[:12] == 'Unknown type':
                listAttr = listAttr + ((0x0009, '420'),) # ERROR-CODE
                unkAttr = int(avtype[13:])
                listUnkAttr = listUnkAttr + (unkAttr,)
                numUnkAttr+=1
                self.responseType = "Binding Error Response"
                
        # To respect the that the total length of the list
        # is a multiple of 4 bytes
        if numUnkAttr%2 != 0:
            listUnkAttr = listUnkAttr + (unkAttr,)
        if listUnkAttr != ():
            listAttr = listAttr + ((0x000a, listUnkAttr),)

        return listAttr
            
    def getPeerInfo(self, key):
        """Return the client's infos: search by key.
        (id, public address, private address, NAT type)"""

        if key in self.peersIDTab:
            return key, self.peersIDTab[key], \
                   self.peersIPTab[self.peersIDTab[key]][0], \
                   self.peersIPTab[self.peersIDTab[key]][1] 
        elif key in self.peersIPTab:
            return '', key, self.peersIPTab[key][0], self.peersIPTab[key][1]
        return ()

    def registrePeer(self, (userId, publicIP, privateIp, natType)):
        """Records the customer in the customer table"""

        if userId != '' :
            # If the client has an ID registre it
            self.peersIDTab[userId] = publicIP        
        self.peersIPTab[publicIP] = (privateIp, natType)

    def printActiveConnection(self):
        """Print the table with the active connection"""
        
        print '*-------------------------------------------------------------------------*'
        print '* Active connections                                                      *'
        t = {}
        for peer in self.peersIDTab:
            t[self.peersIDTab[peer]] = ''
            print "| %12s | %22s | %22s | %4s |" % \
                  (peer, self.peersIDTab[peer], \
                   self.peersIPTab[self.peersIDTab[peer]][0], \
                   self.peersIPTab[self.peersIDTab[peer]][1])
            
        for peer in self.peersIPTab:
            if peer not in t:
                print "|              | %22s | %22s | %4s |" % \
                      (peer, self.peersIPTab[peer][0], \
                       self.peersIPTab[peer][1])            
        print '*-------------------------------------------------------------------------*'


# ============================================================================
#    Hole Punching Protocol: peer
# ============================================================================
class PunchPeer(PunchProtocol, object):

    activeConnection = ()
    
    # Initial timeout valor
    punch_timeout = 0.3
        
    def stopTimeout(self):
        """Stops the active timeout"""
        try:
            self.timeout.cancel()
            #print "timeout stopped"
        except:
            #print "except timeout"
            pass
        # Reinitialise variables
        self.punch_timeout = 0.1
        self.request = 1
        
    def analyseMessage(self, address):
        """
        Analyse the server's response
        """
        self.fromAddress = address
        listAttr = ()


        # TODO:
        # A tid for every connection
        # Check tid is one we sent and haven't had a reply to yet
        if self._pending.has_key(self.tid):
            #del self._pending[self.tid]
            pass
        elif self.mt == 0x1111: # Is a connection request
            # Add the tid to table (in "connection request" case)
            pass
        else:
            logging.error("error, unknown transaction ID %s, have %r" \
                          % (self.tid, self._pending.keys()))
            return
             
        if self.mt == 0x1101:
            # -------------------------------------------------------------
            # Lookup Response
            logging.info("got punch response from %s"%repr(address))
            
            dummy,family,port,addr = struct.unpack( \
                '!ccH4s', self.avtypeList["PUBLIC-ADDRESSE"])
            publicAddress = (socket.inet_ntoa(addr), port)
            dummy,family,port,addr = struct.unpack( \
                '!ccH4s', self.avtypeList["PRIVATE-ADDRESSE"])
            privateAddress = (socket.inet_ntoa(addr), port)
            # TODO: read NAT type
            # If Nat type is sym: wait for message from peer

            # Puts peer in the active connection list and try to contact it
            self.activeConnection = self.activeConnection + (publicAddress,)
            self.activeConnection = self.activeConnection + (privateAddress,)
            self.responseType = "Connection to peer" 

            if self.protocol == 'TCP':
                self.reactor.listenTCP(self.port, self)
                print 'Listen on port:', self.port
                reactor.connectTCP(publicAddress[0], publicAddress[1], self)
                print 'Connect with:', publicAddress
                self.TCPsessionStarted = 1
            
            # Msg to the peer's public address
            self.sendMessage(publicAddress)
            # Msg to the peer's public address
            self.sendMessage(privateAddress)    
                  
        elif self.mt == 0x1003:
            # -------------------------------------------------------------
            # Registration Response
            dummy,family,port,addr = struct.unpack( \
                '!ccH4s', self.avtypeList["PUBLIC-ADDRESSE"]) 
            self.publicAddr = (socket.inet_ntoa(addr), port)
            self.registrationMade()
            
        elif self.mt == 0x1111:
            # -------------------------------------------------------------
            # Connection Request
            print "Connection Request!!!"
            
            self.responseType = "Connection to peer"
            
            dummy,family,port,addr = struct.unpack( \
                '!ccH4s', self.avtypeList["REQUESTOR-PUBLIC-ADDRESSE"])
            publicAddress = (socket.inet_ntoa(addr), port)
            self.activeConnection = self.activeConnection + (publicAddress,)
            
            # Add tid: it's a new connection
            self._pending[self.tid] = (time.time(), publicAddress)

            # If the other peer client is bihind a NAT too
            if 'REQUESTOR-PRIVATE-IP' in self.avtypeList:
                dummy,family,port,addr = struct.unpack( \
                    '!ccH4s', self.avtypeList["REQUESTOR-PRIVATE-ADDRESSE"])
                privateAddress = (socket.inet_ntoa(addr), port)
                self.activeConnection = self.activeConnection + (privateAddress,)
                # Send msg to the peer's private address
                #self.sendMessage(privateAddress)

            
            if self.protocol == 'TCP':
                self.reactor.listenTCP(self.port, self)
                print 'Listen on port:', self.port
                reactor.connectTCP(publicAddress[0], publicAddress[1], self)
                print 'Connect with:', publicAddress
                self.TCPsessionStarted = 1

            # Send msg to the peer's public address
            self.sendMessage(publicAddress)
            
        elif self.mt == 0x1102:
            # -------------------------------------------------------------
            # Connection to peer
            self.responseType = "Connection to peer"
            
            if self.fromAddress in self.activeConnection:
                # The connection is established
                self.connectionMade()
            else:
                # Send msg to the peer's address
                self.sendMessage(self.fromAddress)
                
            
        elif self.mt == 0x1112:
            # -------------------------------------------------------------
            # Error Response
            
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

    def sendMessage(self, server, avpairs=()):

        self._pending[self.tid] = (time.time(), server)
        self.timeout = 0.1
        self.request = 1
        #self.timeout = reactor.callLater(self.timeout, self._timeout)
        self.createMessage(server, avpairs)

        
    def _timeout(self):
        """If a timeout is expired
        Send 9 message at:
           0ms, 100ms, 300ms, 700ms, 1500ms, 3100ms, 4700ms, 6300ms, 7900ms
        """

        print 'timeout', self.request
        self.request += 1
        if self.request == 10:
            self.retransmissionEnded()
            return
        if self.punch_timeout < 1.6:
            self.punch_timeout = 2 * self.punch_timeout
        self.timeout = reactor.callLater(self.punch_timeout, self._timeout) 
        self.sendPack()
        
    def retransmissionEnded(self):
        """Connection have failed (called at 9500ms)"""

        self.stun_timeout = 0.1
        self.request = 1

 
    def getErrorCode(self):
        """If an error occurred: return the error code"""
        
        # Extract the class and number
        error, phrase = struct.unpack( \
            '!i%ds' % (len(self.avtypeList["ERROR-CODE"])-4), \
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
            _listUnkAttr = _listUnkAttr + ('0x%04x' % attr,)
        return _listUnkAttr

    def connectByAddress(self, address):
        """Try to connect to a peer by his address"""
        avpairs = ()
        
        self.tid = getRandomTID()
        self.responseType = 'Lookup Request'
        avpairs = avpairs + ((0x0002, self.getPortIpList(address)),)
        avpairs = avpairs + ((0x0005, self.getPortIpList(self.publicAddr)),)
        avpairs = avpairs + ((0x0006, self.getPortIpList(self.privateAddr)),)
        self.sendMessage(self.server, avpairs)

    def connectByURI(self, URI):
        """Try to connect to a peer by his URI"""
        avpairs = ()
        
        self.tid = getRandomTID()
        self.responseType = 'Lookup Request'
        avpairs = avpairs + ((0x0001, URI),)
        avpairs = avpairs + ((0x0005, self.getPortIpList(self.publicAddr)),)
        avpairs = avpairs + ((0x0006, self.getPortIpList(self.privateAddr)),)
        self.sendMessage(self.server, avpairs)
        
    def registration(self, (userId, publicAddr, privateAddr, natType)):
        """Create and send a register message to the rendezvous server"""
        
        # TODO: indipendent from protocol!!!
        self.protocol = '!TCP'
        
        listAttr = ()
        self.publicAddr = publicAddr
        self.privateAddr = privateAddr

        listAttr = listAttr + ((0x0001, userId),)
        listAttr = listAttr + ((0x0002, self.getPortIpList(publicAddr)),)
        listAttr = listAttr + ((0x0003, self.getPortIpList(privateAddr)),)

        self.responseType = 'Registration Request'
        self.tid = getRandomTID()
        #self.timeout = reactor.callLater(self.punch_timeout, self._timeout)
        self.sendMessage(self.server, listAttr)                    

    def registrationMade(self):
        print "Registration made"
        return
            
##     def connect(self, (userId, ip, port)):
##         """Make a connection with a peer"""
        
##         self.punch.setEstablishUDPsessionArgs((userId, ip, port))
##         self.punch.sendMessage(self.rdvIP, self.rdvPort)
        
    def connectionMade(self):
        """The connection with the peer is established"""

        # TODO: send a callback signal
        print "Connection Made!!!"

    def setRdvServer(self, (host, port)):
        self.rdvIP, self.rdvPort = (host, port)
        
    def setTransport(self, transport):
        self.punch.setTransport(transport)

    def keepAlive(self):
        #TODO
        pass

    def setSelf(self, _self):
        print _self, self
        print "request", _self.request,
        print self.request
        self = _self

    def setReactor(self, reactor):
        self.reactor = reactor
