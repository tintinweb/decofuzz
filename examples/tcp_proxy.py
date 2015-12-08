#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
'''
Origin:
             from_local                from_remote
[local_app]<------------>[local:port]<------------->[remote:port]
'''
# TODO: add weights to fuzzdef
# TODO: add direction or identifier to fuzzdef?
# TODO: allow to add multiple handlers per fuzzdef
# TODO: content detection and smart injection (str, ints, ..) for ASCII/Binary mode
# TODO: add limited cmd-backlog for backklog smartfuzz (starttls, stripptls)
# TODO; fuzzdef mode: replace (default), post/pre mangle (transparent)
import socket
import select
import time
import sys
import md5
import logging
import decofuzz

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)-8s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("decofuzz.engine").setLevel(logging.DEBUG)
logging.getLogger("decofuzz.mangle").setLevel(logging.DEBUG)

class Forward(object):
    '''Forward Class'''
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, destination):
        try:
            self.forward.connect(destination)
            return self.forward
        except Exception, e:
            logger.warning("forward: %s"%repr(e))
            return False
    
class ProxyServer(object):
    '''Proxy Class'''
    ORIGIN_LOCAL = 1
    ORIGIN_REMOTE = 2
    
    def __init__(self, listen, forward, buffer_size=4096, delay=0.0001):
        self.input_list = []
        self.channel = {}
        self.origins = {}
        #
        self.listen = listen
        self.forward = forward
        # Changing the buffer_size and delay, you can improve the speed and bandwidth.
        # But when buffer get to high or delay go too down, you can broke things
        self.buffer_size = buffer_size
        self.delay = delay
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.origins[self.server] = self.ORIGIN_LOCAL
        self.server.bind(listen)
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            logger.debug("STATS: %s"%decofuzz.engine.FuzzMaster.get_stats())
            time.sleep(self.delay)
            ss = select.select
            inputready, _, _ = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break
                try:
                    self.data = self.s.recv(self.buffer_size)
                    if len(self.data) == 0:
                        self.on_close()
                    else:
                        self.on_recv()
                except ImportError, e:
                    logger.warning("main: %s"%repr(e))
                    self.on_close()

    def on_accept(self):
        forwardsock = Forward().start(self.forward)
        self.origins[forwardsock] = self.ORIGIN_REMOTE

        clientsock, clientaddr = self.server.accept()
        self.origins[clientsock] = self.ORIGIN_LOCAL
        
        if forwardsock:
            logger.info("%s has connected"%repr(clientaddr))
            self.input_list.append(clientsock)
            self.input_list.append(forwardsock)
            self.channel[clientsock] = forwardsock
            self.channel[forwardsock] = clientsock
        else:
            logger.warning( "Can't establish connection with remote server.")
            logger.warning( "Closing connection with client side %s"%repr(clientaddr))
            clientsock.close()
        try:
            logger.info( "%s has disconnected"%self.s.getpeername())
            #remove objects from input_list
            self.input_list.remove(self.s)
            self.input_list.remove(self.channel[self.s])
            out = self.channel[self.s]
            # close the connection with client
            self.channel[out].close()  # equivalent to do self.s.close()
            # close the connection with remote server
            self.channel[self.s].close()
            # delete both objects from channel dict
            del self.channel[out]
            del self.channel[self.s]
        except:pass

    def on_recv(self):
        data = self.data
        logger.info( self.origins.get(self.channel[self.s]))

        logger.info( "[   ]        %s => %s"%(self.channel[self.s].getpeername(),self.s.getpeername()))

        try:
            # here we can parse and/or modify the data before send forward
            logger.info( "  [ IN] <---        got %d bytes of data - %s"%(len(data),md5.new(data).hexdigest()))
            data = self.fwd_mangle(data)
            logger.info( "  [OUT] --->    sending %d bytes of data - %s"%(len(data),md5.new(data).hexdigest()))
        except TypeError,e:
            logger.warning( "on_recv %s"%repr(e))
        self.channel[self.s].send(data)
        
    def on_close(self):
        try:
            logger.info( "%s has disconnected"%repr(self.s.getpeername()))
            #remove objects from input_list
            self.input_list.remove(self.s)
            self.input_list.remove(self.channel[self.s])
            out = self.channel[self.s]
            # close the connection with client
            self.channel[out].close()  # equivalent to do self.s.close()
            # close the connection with remote server
            self.channel[self.s].close()
            # delete both objects from channel dict
        except socket.error, se:
            logger.warning( "on_close"%repr(se))
        del self.channel[out]
        del self.channel[self.s]
        
    @decofuzz.engine.FuzzMaster.candidate
    def fwd_mangle(self, data):
        if self.origins.get(self.channel[self.s])==self.ORIGIN_LOCAL:
            return self.fwd_mangle_to_local(data)
        elif self.origins.get(self.channel[self.s])==self.ORIGIN_REMOTE:
            return self.fwd_mangle_to_remote(data)
        return data
    @decofuzz.engine.FuzzMaster.candidate
    def fwd_mangle_to_remote(self, data):
        return data
    @decofuzz.engine.FuzzMaster.candidate
    def fwd_mangle_to_local(self, data):
        return data
        

if __name__ == '__main__':
    ret = 0
    if not len(sys.argv)>1:
        print ("<listen_ip> <listen_port> <forward_ip> <forward_port>")
        sys.exit(1)
    
    
    decofuzz.engine.FuzzMaster.MUTATION_PER_RUN=10000
    decofuzz.engine.FuzzMaster.add_fuzzdef("fwd_mangle_to_local",decofuzz.mangle.General.none, p=99)
    decofuzz.engine.FuzzMaster.add_fuzzdef("fwd_mangle_to_local",decofuzz.mangle.Message.msg_bitflip, p=10, strategy=decofuzz.engine.Queue.STRATEGY_REPLACE)
    
    
    local_listen = (sys.argv[1], int(sys.argv[2]))
    forward_to = (sys.argv[3],int(sys.argv[4]))
    logger.info("%s <==> %s"%(local_listen,forward_to))
    server = ProxyServer(listen=local_listen, forward=forward_to, buffer_size=4096, delay=0.00001)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        logger.warning( "Ctrl C - Stopping server")
        ret+=1
    print decofuzz.engine.FuzzMaster.get_stats()
    sys.exit(ret)