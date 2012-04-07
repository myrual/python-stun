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

import twisted.internet.defer as defer
from twisted.python import log, failure
from twisted.internet import reactor
import ConfigParser

from p2pNetwork.htcp import punchProtocol

stun_section = {
    'servers': ('stun_servers', str, ""),
}


class _Puncher(punchProtocol.PunchPeer):
    
    def __init__(self, port = 0, config = (), id = '', *args, **kargs):
        super(_Puncher, self).__init__(*args, **kargs)
        
        # Load configuration
        p2pConfig = ConfigParser.ConfigParser()
        p2pConfig.read("p2pNetwork.conf")
    
        server = p2pConfig.get('holePunch', 'ConnectionBroker').split(':')
        server = (server[0], int(server[1]))
        self.setServer(server)
        self.privateAddr = (config[2][0], port)
        self.publicAddr = config[3]
        self.id = id
            
    def register(self, port, reactor, deferred):
        
        self.deferred = deferred
        self.port = port
        self.reactor = reactor
        self.listening = reactor.listenUDP(port, self)
        self.registration((self.id, self.publicAddr, self.privateAddr, ''))
        
    def connectionMade(self, addr = '', port = 0):
        """
        Called back when STUN discovered our public address.
        """
        print "Connection made!!!"
        if not self.deferred.called:
            pass
            #self.deferred.callback((addr, int(port)))

    def registrationMade(self):
        print "Registration made!!!"

        if not self.deferred.called:
            self.deferred.callback((self.transport, self))

    def Stop():
        pass
    
def HolePunching(port, reactor, config, id):
    d = defer.Deferred()
    puncher = _Puncher(port, config, id)

    # Define timeout callback
    def _timeout():
        puncher.Stop()
        d.errback(Exception("timed out with servers %s" % servers))
    # Define intermediary succeed callback
    def _succeed(value):
        # Don't stop: continue to listen on the same port
        #discovery.Stop(reactor)
        return value
    def _fail(failure):
        print "Discovery result:", failure.getErrorMessage()
        d.errback(failure)
        return failure

    d.addCallback(_succeed)
    d.addErrback(_fail)
    # Start listening
    puncher.register(port, reactor, d)
    return d, puncher


def connectByURI(URI, netconf, id, transport, port):
    d = defer.Deferred()
    discovery = _Puncher(port, netconf, id)

    # Define intermediary succeed callback
    def _succeed(value):
        # Don't stop: continue to listen on the same port
        #discovery.Stop(reactor)
        return value
    def _fail(failure):
        print "Discovery result:", failure.getErrorMessage()
        d.errback(failure)
        return failure

    d.addCallback(_succeed)
    d.addErrback(_fail)
    
    discovery.connectByURI(URI)
