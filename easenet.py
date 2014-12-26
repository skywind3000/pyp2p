#! /usr/bin/env python
# -*- coding: utf-8 -*-
#======================================================================
#
# easenet.py - 
#
# NOTE:
# for more information, please see the readme file.
# 
#======================================================================

import sys
import time
import collections

import cnetdew
import cnetudp

from cnetdew import RECV_BAD, RECV_BLOCKING

TYPE_CONNECTOR	= 0
TYPE_LISTENER	= 1
TYPE_ESTABLISH	= 2
TYPE_DEAD		= 3

#----------------------------------------------------------------------
# 简单端点类
#----------------------------------------------------------------------
class easepear(object):
	
	def __init__ (self, net, uid, key, linkdesc):
		self.net = net
		self.uid = uid
		self.key = key
		self.host = net.host
		self.linkdesc = linkdesc
		self.type = TYPE_CONNECTOR
		if (self.net.uid, self.net.key) > (uid, key):
			self.type = TYPE_LISTENER
		self.state = 0
		self.queue = collections.deque()
		self.current = self.net.current
		self.life = self.current + 25
		self.port = -1
	
	def _update_connector (self):
		if self.state == 0:
			self.port = self.host.connect(self.uid, self.key, self.linkdesc)
			self.state = 1
		elif self.state == 1:
			status = self.host.status(self.port) 
			if status == RECV_BAD:
				self.close()
			elif status == 1:
				self.type = TYPE_ESTABLISH
		return 0

	def _update_listener (self):
		ident = (self.uid, self.key)
		if not ident in self.net.accepted:
			return -1
		desc = self.net.accepted[ident]
		self.log('del accepted', ident)
		del self.net.accepted[ident]
		self.port = desc[0]
		self.type = TYPE_ESTABLISH
		return 0
	
	def _update_establish (self):
		while len(self.queue) > 0:
			channel, data = self.queue.popleft()
			self.host.send(self.port, channel, data)
		if self.host.status(self.port) != 1:
			self.close()
		return 0
	
	def log (self, *argv):
		self.net.log('[%d,%d]'%(self.uid, self.key), *argv)
	
	def send (self, channel, data):
		if self.type == TYPE_DEAD:
			return -1
		if self.type != TYPE_ESTABLISH:
			self.queue.append((channel, data))
		elif len(self.queue) > 0:
			self.queue.append((channel, data))
		else:
			self.host.send(self.port, channel, data)
		return 0
	
	def recv (self):
		if self.type == TYPE_DEAD:
			return RECV_BAD, ''
		if self.type != TYPE_ESTABLISH:
			return RECV_BLOCKING, ''
		return self.host.recv(self.port)
	
	def close (self):
		if self.port >= 0:
			self.host.close(self.port)
			self.port = -1
		self.type = TYPE_DEAD
		self.net = None
		self.host = None
		self.queue.clear()
	
	def getrtt (self):
		if self.port >= 0:
			return self.host.getrtt(self.port)
		return -1

	def update (self):
		if self.type == TYPE_DEAD:
			return -1
		self.current = self.net.current
		if self.type == TYPE_ESTABLISH:
			self._update_establish()
		else:
			if self.current < self.life:
				if self.type == TYPE_CONNECTOR:
					self._update_connector()
				elif self.type == TYPE_LISTENER:
					self._update_listener()
			else:
				self.close()
		return 0


#----------------------------------------------------------------------
# 简单网络类
#----------------------------------------------------------------------
class easenet(object):
	
	def __init__ (self):
		self.host = cnetdew.hostnet()
		self.uid = 0
		self.key = 0
		self.current = time.time()
		self.accepted = {}
		self.peerlist = {}
		self.timeslap = self.current
	
	def init (self, uid, passwd, port, server):
		self.host.init(uid, passwd, port, server)
		self.uid = self.host.uid
		self.key = self.host.key
		self.accepted = {}
		self.peerlist = {}
		self.timeslap = self.current + 1
	
	def quit (self):
		self.host.quit()
		for n in self.peerlist:
			n.close()
		self.accepted = {}
		self.peerlist = {}

	def __try_accept (self):
		while 1:
			port, uid, key, linkdesc = self.host.accept()
			if port < 0:
				break
			if (uid, key) in self.accepted:
				self.net.close(port)
			else:
				self.log('accepted', uid, key)
				self.accepted[(uid, key)] = [ port, self.current + 10 ]
		return 0
	
	def __scan_accepted (self):
		for ident, desc in self.accepted.items():
			if self.current >= desc[1]:
				self.host.close(desc[0])
				self.log('close here', ident)
				del self.accepted[ident]
		return 0
	
	def __scan_peers (self):
		for ident, peer in self.peerlist.items():
			peer.update()
			if peer.type == TYPE_DEAD:
				del self.peerlist[ident]
				peer.close()
		return 0

	def login (self):
		return self.host.network.state
	
	def localhost (self):
		return self.host.localhost()
	
	def linkdesc (self):
		return self.host.linkdesc()
	
	def log (self, *argv):
		self.host.log(*argv)

	def newpeer (self, uid, key, linkdesc):
		ident = uid, key
		if ident in self.peerlist:
			self.log('[EASE] newpeer(%d, %d) : already in list'%(uid, key))
			return -1
		endpoint = cnetudp.endpoint()
		try:
			endpoint.unmarshal(linkdesc)
		except:
			self.log('newpeer: error linkdesc')
			return -2
		if endpoint.nat == None and len(endpoint.local) == 0:
			self.log('newpeer: empty linkdesc')
			return -3
		self.log('[EASE] newpeer(%d, %d) : ok'%(uid, key))
		peer = easepear(self, uid, key, linkdesc)
		self.peerlist[ident] = peer
		return 0
	
	def delpeer (self, uid, key):
		ident = uid, key
		if not ident in self.peerlist:
			self.log('[EASE] delpeer(%d, %d) : not find'%(uid, key))
			return -1
		peer = self.peerlist[ident]
		del self.peerlist[ident]
		peer.close()
		self.log('[EASE] delpeer(%d, %d) : ok'%(uid, key))
		return 0
	
	def send (self, uid, key, channel, data):
		ident = uid, key
		if not ident in self.peerlist:
			return -1
		peer = self.peerlist[ident]
		peer.send(channel, data)
		return 0
	
	def recv (self, uid, key):
		ident = uid, key
		if not ident in self.peerlist:
			return RECV_BAD, ''
		peer = self.peerlist[ident]
		channel, data = peer.recv()
		return channel, data

	def status (self, uid, key):
		ident = uid, key
		if not ident in self.peerlist:
			return -10
		retval = self.peerlist[ident].type
		return retval
	
	def getroute (self, uid, key):
		ident = uid, key
		if not ident in self.peerlist:
			return None
		peer = self.peerlist[ident]
		#print 'port', peer.port, type(self.host.route), type(self.host)
		return self.host.getroute(peer.port)
	
	def getrtt (self, uid, key):
		ident = uid, key
		if not ident in self.peerlist:
			return -2
		peer = self.peerlist[ident]
		return peer.getrtt()
	
	def canlog (self, value):
		self.host.canlog = value
	
	def trace (self, tracer):
		self.host.trace = tracer

	def update (self):
		self.host.update()
		self.current = self.host.current
		if self.current >= self.timeslap:
			self.__try_accept()
			self.__scan_accepted()
			self.__scan_peers()
			self.timeslap = self.current + 0.2
		return 0



#----------------------------------------------------------------------
# testing case
#----------------------------------------------------------------------
if __name__ == '__main__':
	def wait(*args):
		timeout = time.time() + 4
		while 1:
			time.sleep(0.1)
			count = 0
			for host in args:
				host.update()
				if host.login() == 1:
					count += 1
			if count == len(args): 
				break
			if time.time() > timeout: break
		return 0

	def server(*args):
		while 1:
			time.sleep(0.001)
			for host in args:
				host.update()
	def test1():
		host = easenet()
		host.init(10, 1, 0, ('218.107.55.250', 2009))
	
	def test2():
		host1 = easenet()
		host2 = easenet()
		host1.init(20013080, 123, 0, ('218.107.55.250', 2009))
		host2.init(20013070, 456, 0, ('218.107.55.250', 2009))
		wait(host1, host2)
		ident1 = (20013070, 456)
		ident2 = (20013080, 123)
		host1.newpeer(ident1[0], ident1[1], host2.linkdesc())
		host2.newpeer(ident2[0], ident2[1], host1.linkdesc())
		timeslap = time.time()
		seq = 0
		while 1:
			time.sleep(0.01)
			host1.update()
			host2.update()
			t1 = host1.status(ident1[0], ident1[1])
			t2 = host2.status(ident2[0], ident2[1])
			channel, data = host2.recv(ident2[0], ident2[1])
			if channel >= 0:
				host2.send(ident2[0], ident2[1], channel, data)
			if time.time() >= timeslap:
				timeslap = time.time() + 1
				text = '%d %f'%(seq, time.time())
				seq += 1
				host1.send(ident1[0], ident1[1], 2, text)
				print host1.getroute(ident1[0], ident1[1])
			channel, data = host1.recv(ident1[0], ident1[1])
			if channel >= 0:
				record = data.split(' ')
				last = time.time() - float(record[1])
				print '[RECV] seq=%3d rtt=%f'%(int(record[0]), last)
			#print t1, t2, time.time()

	import cnetcom
	cnetcom.plog = cnetcom.plog_stdout
	test2()

