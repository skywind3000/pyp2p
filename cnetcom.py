#! /usr/bin/env python
# -*- coding: utf-8 -*-
#======================================================================
#
# cnetcom.py - udp host basic interface
#
# NOTE:
# 地址路由及内网穿透功能模块，使用 cnetudp模块中的 udpnet功能完成
# 内网穿透及路由功能，协议见后面文档。
# 
#======================================================================
import sys
import time
import socket
import struct
import collections

import cnetudp


#----------------------------------------------------------------------
# messages header
#----------------------------------------------------------------------
class msghead(object):
	def __init__ (self, suid = 0, skey = 0, duid = 0, dkey = 0, sport = 0, \
					dport = 0, cmd = 0, conv = 0):
		self.suid = suid
		self.skey = skey
		self.duid = duid
		self.dkey = dkey
		self.sport = sport
		self.dport = dport
		self.cmd = cmd
		self.conv = conv
		self.raw = ''
	def __repr__ (self):
		text = '<suid=%d skey=%d duid=%d dkey=%d sport=%d dport=%d cmd=%x '
		text += 'conv=%d>'
		text = text%(self.suid, self.skey, self.duid, self.dkey, \
			self.sport, self.dport, self.cmd, self.conv)
		return text
	def __str__ (self):
		return self.__repr__()
	def marshal (self):
		msg = struct.pack('!llllllll', self.suid, self.skey, self.duid, \
			self.dkey, self.sport, self.dport, self.cmd, self.conv)
		self.raw = msg
		return self.raw
	def unmarshal (self, data):
		if len(data) != 32:
			raise Exception('header size is not 32')
		record = struct.unpack('!llllllll', data)
		self.suid = record[0]
		self.skey = record[1]
		self.duid = record[2]
		self.dkey = record[3]
		self.sport = record[4]
		self.dport = record[5]
		self.cmd = record[6]
		self.conv = record[7]
		self.raw = data
		return self


#----------------------------------------------------------------------
# protocol - 协议定义
#----------------------------------------------------------------------
CMD_HELLO	= 0x4001		# punching: 向对方所有地址发送hello
CMD_HACK	= 0x4002		# punching: 收到hello后向源所有地址返回
CMD_TOUCH	= 0x4003		# punching: 收到hack后，向可联通的地址发送
CMD_TACK	= 0x4004		# punching: 收到touch后返回，完成punching
CMD_PING	= 0x4005		# 简单ping
CMD_PACK	= 0x4006		# ping 返回

CMD_SYN1	= 0x4010		# connect: step1
CMD_SACK1	= 0x4011		# connect: step2
CMD_SYN2	= 0x4012		# connect: step3
CMD_SACK2	= 0x4013		# connect: step4
CMD_DENY	= 0x4014		# connect: deny
CMD_NOPORT	= 0x4015		# 没有该端口
CMD_NOCONV	= 0x4016		# 没有该会话

CMD_DATA	= 0x4020		# data: send
CMD_ACK		= 0x4021		# data: ack
CMD_ALIVE	= 0x4022		# data: keep alive
CMD_ALACK	= 0x4023		# data: alive ack

CMD_FIN1	= 0x4030		# close: fin_1
CMD_FACK1	= 0x4031		# close: fin_ack_1
CMD_FIN2	= 0x4032		# close: fin_2
CMD_FACK2	= 0x4033		# close: fin_ack_2

LOG_HELLO	= 0x01
LOG_HACK	= 0x02
LOG_TOUCH	= 0x04
LOG_TACK	= 0x08
LOG_PUNCHING = (LOG_HELLO | LOG_HACK | LOG_TOUCH | LOG_TACK)

LOG_ROUTE	= 0x10


#----------------------------------------------------------------------
# routing - 路由管理器
# 因每个主机有若干地址：各个本地网卡地址，nat地址等，使得到达双方的通
# 路有很多：到对方各个本地网卡地址的，直接到对方nat与通过stun转发的
# 因此路由管理器将用于管理并选择一条两台主机间最好的通路。在punching
# 中当收到TACK的时候，调用routing对象的newroute将完成punching并验证
# 合法的一条通路记录进去，并随时使用bestroute取得最佳路径。
#----------------------------------------------------------------------
class routing(object):

	# 对象初始化
	def __init__ (self, uid, key, linkdesc, current = None, hello = 2.0):
		self.uid = uid
		self.key = key
		self.linkdesc = linkdesc
		self.map = {}
		if not current: 
			current = time.time()
		self.current = current
		self.state = 0
		self.best = None
		self.life = 30
		self.time_hello = current + hello
		self.time_life = current + self.life
		self.time_tick = 0.3
		self.time_slap = current + self.time_tick
		self.time_best = current + hello * 4 + self.time_tick * 2
		self.replys = 0
		self.hello_cnt = 0
		self.hello_max = 100
	
	# 比较两条通路
	def cmproute (self, route1, route2):
		mode1 = route1[2] + route1[4]
		mode2 = route2[2] + route2[4]
		if mode1 < mode2:
			return -100
		elif mode1 > mode2:
			return 100
		type1 = cnetudp.iptype(route1[1][0]) + cnetudp.iptype(route1[3][0])
		type2 = cnetudp.iptype(route1[1][0]) + cnetudp.iptype(route1[3][0])
		if type1 < type2:
			return -10
		elif mode1 > type2:
			return 10
		if route1[0] < route2[0]: 
			return -1
		elif route1[0] == route2[0]:
			return 0
		return 1

	# 增加通路
	def newroute (self, rtt, addr1, mode1, addr2, mode2):
		route = (rtt, addr1, mode1, addr2, mode2)
		key = (addr1, mode1, addr2, mode2)
		self.map[key] = min(self.map.get(key, 30), rtt)
		if not self.best:
			self.best = route
		elif self.cmproute(route, self.best) < 0:
			self.best = route
		if (self.state == 0) and (self.best[2] + self.best[4] == 0):
			self.state = 1
		self.replys += 1
		return 0

	# 取得最佳通路
	def bestroute (self):
		if self.state != 1:
			return None
		return self.best
	
	# 激活
	def active (self):
		self.time_life = self.current + self.life
	
	# 更新状态：返回0则跳过，返回1则hello，返回2则ping，返回-1则该关闭 -2禁止
	def update (self, current = None):
		if not current: 
			current = time.time()
		if current < self.current:
			current = self.current
		self.current = current
		if self.state < 0:
			return -1
		if current > self.time_life:
			oldstate = self.state
			self.state = -1
			if oldstate != 0:
				return -1
			return -2
		if self.state > 0:
			self.time_tick = 20
			if current >= self.time_slap:
				self.time_slap = current + self.time_tick
				return 2
			return 0
		if current >= self.time_slap:
			self.time_slap = current + self.time_tick
			self.hello_cnt += 1
			if self.hello_cnt >= self.hello_max:
				self.state = -1
				return -1
			return 1
		if self.best:
			if self.best[2] + self.best[4] == 0:
				type1 = cnetudp.iptype(self.best[1][0])
				type2 = centudp.iptype(self.best[3][0])
				if type1 < 10 and type2 < 10:
					self.state = 1
			if current >= self.time_hello:
				if self.best[2] + self.best[4] == 0:
					self.state = 1
			if current >= self.time_best:
				self.state = 1
		return 0


#----------------------------------------------------------------------
# hostbase: 基础网络构建，完成地址探测与几项基本服务
#----------------------------------------------------------------------
class hostbase(object):
	
	# 对象初始化
	def __init__ (self):
		self.network = cnetudp.udpnet()
		self.uid = 0
		self.key = 0
		self.server = None
		self.current = time.time()
		self.sndque = collections.deque()
		self.rcvque = collections.deque()
		self.trace = None
		self.route = {}
		self.badroute = {}
		self.time_route = 0
		self.cnt_port = 0
		self.cnt_conv = 0
		self.logmask = 0
	
	# 打开网络：指明全局唯一的 uid，并设置密码，然后是端口及 stun服务器
	def init (self, uid, passwd, port = 0, server = None):
		self.quit()
		self.uid = int(long(uid) & 0x7fffffff)
		self.key = int(long(passwd) & 0x7fffffff)
		self.network.open(port, server)
		self.current = time.time()
		self.time_route = self.current
		self._cnt_port = (((uid >> 16) + (uid & 0xffff)) % 9 + 1) * 1000
		self._cnt_conv = ((uid >> 16) + (uid & 0xffff)) & 0xffff
		self._cnt_conv += long(time.time() * 1000000) % 1000000
		return 0
	
	# 关闭网络
	def quit (self):
		self.network.close()
		self.sndque.clear()
		self.rcvque.clear()
		self.route = {}
		self.badroute = {}
		return 0
	
	# 取得本地网络的地址列表
	def endpoint (self):
		return self.network.ep
	
	# 取得地址描述信息：及 self.network.ep.marshal的信息
	def linkdesc (self):
		return self.network.linkdesc
	
	# 取得本地地址描述
	def localhost (self):
		text = '127.0.0.1:%d'%self.network.port
		return text
	
	# 发送 UDP数据：协议头，数据，远程地址，是否转发
	def sendudp (self, head, data, remote, forward = 0):
		rawdata = head.marshal() + data
		self.network.send(rawdata, remote, forward)
		return 0
	
	# 接收 UDP数据：协议头，数据，远程地址，是否转发
	def recvudp (self):
		head, data, remote, forward = None, '', None, -1
		while 1:
			rawdata, remote, forward = self.network.recv()
			if forward < 0: # 没有消息，阻塞了
				return None, '', None, -1
			try:	
				head = msghead().unmarshal(rawdata[:32])
				data = rawdata[32:]
				return head, data, remote, forward
			except:			# 消息错误，忽略
				pass
		return None, '', None, -1
	
	# 发送 ping
	def _send_ping (self, duid, dkey, remote, forward):
		head = msghead(self.uid, self.key, duid, dkey, cmd = CMD_PING)
		text = str(self.current)
		self.sendudp(head, text, remote, forward)
		return 0
	
	# 接收 ping
	def _recv_ping (self, head, data, remote, forward):
		newhead = msghead(self.uid, self.key, head.suid, head.skey)
		newhead.cmd = CMD_PACK
		self.sendudp(newhead, data, remote, forward)
		return 0
	
	# 接收 ping_ack
	def _recv_pack (self, head, data, remote, forward):
		try:
			timestamp = float(data)
		except:
			return -1
		rtt = self.current - timestamp
		ident = head.suid, head.skey
		if ident in self.route:
			self.route[ident].active()
		return 0
	
	# 连接方(addr1, mode1) 被连接方(addr2, mode2)
	# cmd_hello = timestamp + addr2 + mode2 + linkdesc1
	def _send_hello (self, duid, dkey, linkdesc):
		head = msghead(self.uid, self.key, duid, dkey, cmd = CMD_HELLO)
		endpoint = cnetudp.endpoint().unmarshal(linkdesc)
		destination = cnetudp.destination(endpoint)
		timestamp = '%.f'%self.current
		linkdesc1 = self.linkdesc()
		if linkdesc[:10] == '127.0.0.1:':
			linkdesc1 = self.localhost()
		for addr2, mode2 in destination:
			text = '%s,%s,%s,'%(timestamp, cnetudp.ep2text(addr2), mode2)
			text += linkdesc1
			if self.trace and (self.logmask & LOG_HELLO):
				self.trace('<hello: %s %d>'%(cnetudp.ep2text(addr2), mode2))
				#print '_send_hello: %s %d'%(addr2, mode2)
			self.sendudp(head, text, addr2, mode2)
		return 0
	
	# 接收 hello: 根据接收方的 linkdesc，向接收方所有可能通路返回 hack
	def _recv_hello (self, head, data, remote, forward):
		record = data.split(',')
		if len(record) != 4:
			return -1
		timestamp = record[0]
		try:
			addr2 = cnetudp.text2ep(record[1])	# 取得从哪里来的：地址
			mode2 = int(record[2])				# 取得从哪里来的：是否转发
			linkdesc = record[3]
			endpoint = cnetudp.endpoint().unmarshal(linkdesc)
		except:
			return -1
		destination = cnetudp.destination(endpoint, remote, forward)
		if self.trace and (self.logmask & LOG_HELLO):
			self.trace('<recv hello: %s %d %s %d>'%(cnetudp.ep2text(remote),\
				forward, cnetudp.ep2text(addr2), mode2))
		for addr1, mode1 in destination:
			self._send_hack(head.suid, head.skey, timestamp, \
				addr1, mode1, addr2, mode2)
		return 0
	
	# 连接方(addr1, mode1) 被连接方(addr2, mode2)
	# cmd_hack = timestamp + addr1 + mode1 + addr2 + mode2
	def _send_hack (self, uid, key, ts, addr1, mode1, addr2, mode2):
		head = msghead(self.uid, self.key, uid, key, cmd = CMD_HACK)
		text = '%s,%s,%s,%s,%s'%(ts, cnetudp.ep2text(addr1), mode1, \
			cnetudp.ep2text(addr2), mode2)
		self.sendudp(head, text, addr1, mode1)
		if self.trace and (self.logmask & LOG_HACK):
			self.trace('<hack %s %d %s %d>'%(cnetudp.ep2text(addr1), mode1,\
				cnetudp.ep2text(addr2), mode2))
			#print '<hack %s %d %s %d>'%(addr1, mode1, addr2, mode2)
		return 0
	
	# 连接方(addr1, mode1) 被连接方(addr2, mode2)
	def _recv_hack (self, head, data, remote, forward):
		record = data.split(',')
		if len(record) != 5:
			return -1
		try:
			timestamp = float(record[0])
			addr1 = cnetudp.text2ep(record[1])
			mode1 = int(record[2])
			addr2 = cnetudp.text2ep(record[3])
			mode2 = int(record[4])
		except:
			return -1
		rtt = self.current - timestamp
		rtt = min(30.0, max(0.001, rtt))
		route = [ (rtt, addr1, mode1, addr2, mode2) ]
		if remote != addr2 or forward != mode2:
			route.append((rtt, addr1, mode1, remote, forward))
		timestamp = '%.6f'%self.current
		for rtt, addr1, mode1, addr2, mode2 in route: 
			self._send_touch(head.suid, head.skey, timestamp, 
				addr1, mode1, addr2, mode2)
		if self.trace and (self.logmask & LOG_HACK):
			self.trace('<recv hack: %s %d %s %d>'%(cnetudp.ep2text(addr1), \
				mode1, cnetudp.ep2text(addr2), mode2))
		return 0
	
	# 发送touch消息
	def _send_touch (self, uid, key, ts, addr1, mode1, addr2, mode2):
		head = msghead(self.uid, self.key, uid, key, cmd = CMD_TOUCH)
		text = '%s,%s,%s,%s,%s'%(ts, cnetudp.ep2text(addr1), mode1, \
			cnetudp.ep2text(addr2), mode2)
		self.sendudp(head, text, addr2, mode2)
	
	# 发送tack消息
	def _send_tack (self, uid, key, ts, addr1, mode1, addr2, mode2):
		head = msghead(self.uid, self.key, uid, key, cmd = CMD_TACK)
		text = '%s,%s,%s,%s,%s'%(ts, cnetudp.ep2text(addr1), mode1, \
			cnetudp.ep2text(addr2), mode2)
		self.sendudp(head, text, addr1, mode1)
	
	# 接收 touch
	def _recv_touch (self, head, data, remote, forward):
		record = data.split(',')
		if len(record) != 5:
			return -1
		try:
			timestamp = record[0]
			addr1 = cnetudp.text2ep(record[1])
			mode1 = int(record[2])
			addr2 = cnetudp.text2ep(record[3])
			mode2 = int(record[4])
		except:
			return -1
		self._send_tack(head.suid, head.skey, timestamp, \
			addr1, mode1, addr2, mode2)
		return 0
	
	# 接收 tack
	def _recv_tack (self, head, data, remote, forward):
		record = data.split(',')
		if len(record) != 5:
			return -1
		try:
			timestamp = float(record[0])
			addr1 = cnetudp.text2ep(record[1])
			mode1 = int(record[2])
			addr2 = cnetudp.text2ep(record[3])
			mode2 = int(record[4])
		except:
			return -1
		rtt = self.current - timestamp
		rtt = min(30.0, max(0.001, rtt))
		if self.trace and (self.logmask & LOG_TACK):
			self.trace('<recv tack: %s %d %s %d>'%(cnetudp.ep2text(addr1), \
				mode1, cnetudp.ep2text(addr2), mode2))
		self._newroute(head.suid, head.skey, rtt, addr1, mode1, addr2, mode2)
		return 0
	
	# 添加一条新路径：连接方收到 tack以后调用
	def _newroute (self, uid, key, rtt, addr1, mode1, addr2, mode2):
		ident = (uid, key)
		#print '[PATH] %.3f %s %d %s %d'%(rtt, addr1, mode1, addr2, mode2)
		if self.trace and (self.logmask & LOG_ROUTE):
			self.trace('<newroute: %s %d %s %d>'%(cnetudp.ep2text(addr1), \
				mode1, cnetudp.ep2text(addr2), mode2))
		if ident in self.route:
			route = self.route[ident]
			route.active()
			route.newroute(rtt, addr1, mode1, addr2, mode2)
			route.update(self.current)
		return 0
	
	# 取得最佳路径：对方的uid, key以及 linkdesc
	def bestroute (self, uid, key, linkdesc):
		ident = (uid, key)
		if ident in self.badroute:
			if self.current - self.badroute[ident] < 25:
				return None
			del self.badroute[ident]
		if ident in self.route:
			route = self.route[ident]
			if route.linkdesc != linkdesc:	# 重要：解决多次初始化连接问题
				del self.route[ident]
		if not ident in self.route:		# 自动创建 routing对象并发送 hello
			route = routing(uid, key, linkdesc, self.current)
			self.route[ident] = route
			self._send_hello(uid, key, linkdesc)
			return None
		route = self.route[ident]
		best = route.bestroute()
		return best
	
	# 激活路径：不要让它删除
	def active (self, uid, key):
		ident = (uid, key)
		if ident in self.route:
			route = self.route[ident]
			route.active()
		return 0
	
	# 删除路径：下次重新搜索
	def delroute (self, uid, key):
		ident = (uid, key)
		if ident in self.route:
			del self.route[ident]
		return 0
	
	# 路由更新：扫描存在的路由并在适当时候重复发送 hello与 ping或将其删
	def _route_update (self):
		for ident, route in self.route.items():
			code = route.update(self.current)
			if code == 1:
				self._send_hello(route.uid, route.key, route.linkdesc)
			elif code == -1:
				del self.route[ident]
			elif code == -2:
				del self.route[ident]
				self.badroute[ident] = self.local
		return 0
	
	# 消息分发：处理路由及穿透相关消息，其他消息交给 _process处理
	def _dispatch (self, head, data, remote, forward):
		cmd = head.cmd
		if cmd == CMD_HELLO:
			self._recv_hello(head, data, remote, forward)
		elif cmd == CMD_HACK:
			self._recv_hack(head, data, remote, forward)
		elif cmd == CMD_TOUCH:
			self._recv_touch(head, data, remote, forward)
		elif cmd == CMD_TACK:
			self._recv_tack(head, data, remote, forward)
		elif cmd == CMD_PING:
			self._recv_ping(head, data, remote, forward)
		elif cmd == CMD_PACK:
			self._recv_pack(head, data, remote, forward)
		else:
			self._process (head, data, remote, forward)
		return 0
	
	# 处理路由及穿透以外消息，由子类自己实现
	def _process (self, head, data, remote, forward):
		return 0

	# 生成一个新的端口号
	def _gen_port (self):
		self._cnt_port += 1
		if self._cnt_port >= 0x7fff: 
			self._cnt_port = 0
		return self._cnt_port
	
	# 生成一个新的会话号
	def _gen_conv (self):
		self._cnt_conv += 1 + int(self.current) % 10
		if self._cnt_conv >= 0x7fffffff:
			self._cnt_conv = 1 + int(self.current) % 10
		return self._cnt_conv
	
	# 服务器的 ping值取得
	def pingsvr (self):
		if self.network.state != 1:
			return -1.0
		return self.network.pingsvr * 0.001

	# 更新状态
	def update (self):
		self.current = time.time()
		self.network.update()
		while 1:
			head, data, remote, forward = self.recvudp()
			if forward < 0: break
			if head.duid == self.uid and head.dkey == self.key:
				self._dispatch (head, data, remote, forward)
		if self.current > self.time_route:
			self.time_route = self.current + 0.1
			self._route_update()
		return 0



#----------------------------------------------------------------------
# route2text: 通路转化为字符串
#----------------------------------------------------------------------
def route2text(rtt, addr1, mode1, addr2, mode2):
	text = '%.06f,%s,%d,%s,%d'%(rtt, cnetudp.ep2text(addr1), mode1, \
		cnetudp.ep2text(addr2), mode2)
	return text

#----------------------------------------------------------------------
# route2text: 字符串转化为通路
#----------------------------------------------------------------------
def text2route(text):
	text.strip(' ')
	record = text.split(',')
	if len(record) != 5:
		return None
	try:
		rtt = float(record[0])
		addr1 = cnetudp.text2ep(record[1])
		mode1 = int(record[2])
		addr2 = cnetudp.text2ep(record[3])
		mode2 = int(record[4])
	except:
		return None
	return rtt, addr1, mode1, addr2, mode2

#----------------------------------------------------------------------
# plog: 输出日志
#----------------------------------------------------------------------
def plog_raw(prefix, mode, *args):
	head = time.strftime('%Y%m%d %H:%M:%S', time.localtime())
	text = ' '.join([ str(n) for n in args ])
	line = '[%s] %s'%(head, text)
	if (mode & 1) != 0:
		current = time.strftime('%Y%m%d', time.localtime())
		logfile = sys.modules[__name__].__dict__.get('logfile', None)
		logtime = sys.modules[__name__].__dict__.get('logtime', '')
		if current != logtime:
			logtime = current
			if logfile: logfile.close()
			logfile = None
		if logfile == None:
			logfile = open('%s%s.log'%(prefix, current), 'a')
		sys.modules[__name__].__dict__['logtime'] = logtime
		sys.modules[__name__].__dict__['logfile'] = logfile
		logfile.write(line + '\n')
		logfile.flush()
	if (mode & 2) != 0:
		sys.stdout.write(line + '\n')
	if (mode & 4) != 0:
		sys.stderr.write(line + '\n')
	return 0

# 空的日志输出接口
def plog_none(*args):
	pass

# 输出到文件：'n20xxMMDD.log'中
def plog_file(*args):
	plog_raw('n', 1, *args)

# 输出到标准输出
def plog_stdout(*args):
	plog_raw('n', 2, *args)

# 输出到标准错误
def plog_stderr(*args):
	plog_raw('n', 4, *args)

# 输出到文件及标准输出
def plog_file_and_stdout(*args):
	plog_raw('n', 3, *args)

# 输出到文件及标准错误
def plog_file_and_stderr(*args):
	plog_raw('n', 5, *args)

# 日志接口函数指针：外部调用 plog写日志
plog = plog_none


#----------------------------------------------------------------------
# 消息编号反查
#----------------------------------------------------------------------
_cmd_names = {}

for key, value in sys.modules[__name__].__dict__.items():
	if key[:4] == 'CMD_':
		_cmd_names[value] = key

cmdname = lambda cmd: _cmd_names.get(cmd, 'CMD_%x'%cmd)

'''
-----------------------------------------------------------------------
                             探测协议
-----------------------------------------------------------------------
CMD_HELLO: timestamp, addr2, mode2, linkdesc
CMD_HACK:  timestamp, addr1, mode1, addr2, mode2
CMD_TOUCH: timestamp, addr1, mode1, addr2, mode2
CMD_TACK   timestamp, addr1, mode1, addr2, mode2

远程地址：一个远程地址由 addr(ip,端口) mode(模式：是否转发) 两部分组成
地址编号：addr1, mode1为发送hello方地址，addr2, mode2为接收hello方地址

   连接方(编号1)              接收方(编号2)
   ------------------------------------------
    CMD_HELLO      --------> (向若干地址发送)
	               -------->
	向若干地址发送 <-------- CMD_HACK
                   <--------
	CMD_TOUCH      --------> 
	               <-------- CMD_TACK
	保存通路

连接方（探测方）间隔重复发送 CMD_HELLO，直到收到一定数量的 CMD_TACK，
或者达到一定时间（比如10秒）。

1. 连接端发送CMD_HELLO，到被连接端的每个能连接地址，如果有nat地址的话
也会使用直接发送和stun转发 CMD_HELLO到该 nat地址。

CMD_HELLO:
    timestamp    发送的时间
    addr2        被连接方的目标地址
    mode2        被连接方的连接方式：是否转发
    linkdesc     连接方的地址描述

2. 被连接端收到CMD_HELLO以后，按照连接方的 linkdesc得到连接方所有可能
的返回通路（不管内网地址还是 nat地址），并用每个通路返回给被连接方
CMD_HACK。如果 linkdesc包含连接方的 nat地址，就使用直接发送与 stun转发
两种方法发送两份 CMD_HACK给连接方。最后，还要向 接收到 CMD_HELLO时取得
的远程地址（可能有其他未知出口没被 linkdesc描述到）发送一份 CMD_HACK。

CMD_HACK:
    timestamp    原路返回的时间
    addr1        连接方地址
    mode1        连接方方式
    addr2        被连接方的目标地址
    mode2        被连接方的连接方式

3. 被连接方在收到CMD_HACK的时候进行统计，收集：
   (rtt, addr1, mode1, addr2, mode2) 为第一条可行通路
   (rtt, addr1, mode1, 收到CMD_HACK的远程地址，方法) 为第二条可行通路
   因为从被连接端到连接端可能存在未知的出口，所以有第二条通路的存在
   然后向两条通路分别发送 CMD_TOUCH再次验证。

CMD_TOUCH:
    timestamp    原路返回的时间
    addr1        连接方地址
    mode1        连接方方式
    addr2        被连接方的目标地址
    mode2        被连接方的连接方式

4. 被连接方收到cmd_touch后，从addr1, mode1位置返回 cmd_tack

CMD_TACK:
    timestamp    原路返回的时间
    addr1        连接方地址
    mode1        连接方方式
    addr2        被连接方的目标地址
    mode2        被连接方的连接方式

5. 收到cmd_tack后，记录并统计通路： 
   (rtt, addr1, mode1, addr2, mode2)
'''

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
				if host.network.state == 1:
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
		host1 = hostbase()
		host2 = hostbase()
		host1.trace = plog_stdout
		host1.init(20081308012, 12345, 0, ('218.107.55.250', 2009))
		host2.init(20081308013, 12345, 0, ('218.107.55.250', 2009))
		wait(host1, host2)
		linkdesc = host2.localhost()
		#linkdesc = host2.linkdesc()
		print linkdesc
		timeslap = time.time()
		while 1:
			time.sleep(0.001)
			host1.update()
			host2.update()
			if time.time() >= timeslap:
				timeslap = time.time() + 2
				result = host1.bestroute(host2.uid, host2.key, linkdesc)
				print result
				if result:
					#host1.delroute(host2.uid, host2.key)
					pass
				print host1.pingsvr()
				host1.active(host2.uid, host2.key)
		return 0
	
	def test2():
		host1 = hostbase()
		host1.init(20013070, 222222, 0, ('218.107.55.250', 2009))
		wait(host1)
		print 'linkdesc:',
		host1.update()
		linkdesc = raw_input()
		host1.update()
		timeslap = time.time() + 1
		timereport = time.time() + 5
		while 1:
			time.sleep(0.1)
			host1.update()
			if time.time() > timeslap:
				timeslap = time.time() + 2
				print host1.bestroute(20013080, 111111, linkdesc)
				host1.active(20013080, 111111)
			if time.time() > timereport:
				timereport = time.time() + 5
				print host1.network.statistic_report()
				print 'svrping', host1.pingsvr()
	
	def test3():
		host1 = hostbase()
		host1.init(20013080, 111111, 0, ('218.107.55.250', 2009))
		wait(host1)
		print host1.uid, host1.key, host1.linkdesc()
		for i in xrange(10):
			print host1._gen_port(), host1._gen_conv()
		server(host1)
	
	def test4():
		rtt = 0.2
		addr1 = ('192.168.10.214', 100)
		mode1 = 0
		addr2 = ('202.108.8.40', 200)
		mode2 = 1
		text = route2text(rtt, addr1, mode1, addr2, mode2)
		print text
		route = text2route(text)
		print route

	plog('hahahahah')
	test1()
	# cnetgem.py cnetdew cnetlax.py

