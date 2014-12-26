#! /usr/bin/env python
# -*- coding: utf-8 -*-
#======================================================================
#
# cnetudp.py - udp host interface
#
# NOTE:
# UDP的收发，地址检测，NAT类型分析，休闲服务器会话/转发功能
# 
#======================================================================
import sys
import time
import socket
import struct
import errno
import collections


#----------------------------------------------------------------------
# 取得本机地址列表并且排序
#----------------------------------------------------------------------
def hostaddr(hostc = ''):
	table, result = [], []
	try:
		import fcntl
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		total = 32 * 128
		bytes = array.array('B', '\0' * total)
		point = struct.pack('iL', total, bytes.buffer_info()[0])
		size = struct.unpack('iL', fcntl.ioctl(s.fileno(), 0x8912, point))[0]
		result = [ bytes[i:i+32].tostring() for i in range(0, size, 32) ]
		table = [ '.'.join(['%d'%ord(v) for v in n[-12:-8]]) for n in result]
		s.close()
	except: table = socket.gethostbyname_ex(socket.gethostname())[2]
	f = lambda a: socket.inet_aton(a)
	if not hostc in [ '0.0.0.0', '127.0.0.1', '' ]: return hostc
	for i in xrange(len(table)):
		addr, a = table[i], f(table[i])
		if addr == '127.0.0.1': 
			continue
		elif (a >= f('10.0.0.0') and a <= f('10.255.255.255')): 
			result.append((i + 300, addr))
		elif (a >= f('172.16.0.0') and a <= f('172.31.255.255')):
			result.append((i + 400, addr))
		elif (a >= f('192.168.0.0') and a <= f('192.168.255.255')):
			result.append((i + 200, addr))
		else:
			result.append((i + 100, addr))
	result.sort()
	result = [ (ip, desc) for desc, ip in result ]
	return result


__savetime = time.time()

def _millisec():
	return (long((time.time() - __savetime)* 1000) & 0xffffffff)

hostname = socket.gethostname()


#----------------------------------------------------------------------
# 地址格式化
#----------------------------------------------------------------------
def ep2text(ep):
	if not ep: return '0.0.0.0:0'
	if type(ep) != tuple: return '0.0.0.0:0'
	return '%s:%d'%(ep[0], ep[1])

def text2ep(text):
	pos = text.find(':')
	ip, port = '', 0
	if pos >= 0:
		ip = text[:pos]
		try: port = int(text[pos + 1:])
		except: pass
	else:
		ip = text
	return (ip, port)

def sockaddr(ep):
	data = '\x02\x00' + struct.pack('!H', ep[1]) + socket.inet_aton(ep[0])
	data += '\x00\x00\x00\x00\x00\x00\x00\x00'
	return data


#----------------------------------------------------------------------
# 打印二进制
#----------------------------------------------------------------------
def print_binary(data, char = False):
	content = ''
	charset = ''
	lines = []
	for i in xrange(len(data)):
		ascii = ord(data[i])
		if i % 16 == 0: content += '%04X  '%i
		content += '%02X'%ascii
		content += ((i & 15) == 7) and '-' or ' '
		if (ascii >= 0x20) and (ascii < 0x7f): charset += data[i]
		else: charset += '.'
		if (i % 16 == 15): 
			lines.append(content + ' ' + charset)
			content, charset = '', ''
	if len(content) < 56: content += ' ' * (54 - len(content))
	lines.append(content + ' ' + charset)
	limit = char and 100 or 54
	for n in lines: print n[:limit]
	return 0


#----------------------------------------------------------------------
# 地址分类
#----------------------------------------------------------------------
EP_NORMAL		=	0		# 默认类型
EP_INNAT		=	1		# 在NAT中
EP_GLOBAL		=	2		# 在公网上


#----------------------------------------------------------------------
# endpoint: 包含本地地址列表以及nat地址的地址信息
#----------------------------------------------------------------------
class endpoint(object):

	# 对象初始化：指明本地地址列表，以及 nat地址
	def __init__ (self, local = [], nat = None):
		self.nat = nat
		self.local = [n for n in local]
		self.text = ''
		self.type = EP_NORMAL
		self.split1 = '+'
		self.split2 = '/'
		self.analyse()

	# 地址类型分析
	def analyse (self):
		self.type = EP_NORMAL
		if not self.nat:
			return self.type
		self.type = EP_INNAT
		for ep in self.local:
			if ep == self.nat:
				self.type = EP_GLOBAL
				break
		return self.type

	# 翻译为字符串：用来描述 endpoint的字符串称为 linkdesc
	def marshal (self):
		local = []
		for ip, port in self.local:		# 记录本地地址列表
			local.append('%s:%d'%(ip, port))
		text = self.split1.join(local)
		if self.nat:					# 记录nat地址
			text += self.split2 + '%s:%d'%(self.nat[0], self.nat[1])
		self.text = text
		return text

	# 从字符串解码
	def unmarshal (self, text):
		if type(text) != type(''):
			raise Exception('error endpoint format')
		text = text.strip(' ')
		pos = text.find(self.split2)
		self.nat = None
		self.local = []
		if pos >= 0:
			self.nat = text2ep(text[pos + 1:])
			text = text[:pos]
		for n in text.split(self.split1):
			ep = text2ep(n)
			if n != '' and (ep[0] != '' or ep[1] != 0):
				self.local.append(ep)
		self.analyse()
		return self


#----------------------------------------------------------------------
# STUN SERVER CMD 
#----------------------------------------------------------------------
ITMU_TOUCH		= 0x6000		# 命令：UDP初始化命令
ITMU_ECHO		= 0x6001		# 命令：回射命令
ITMU_MIRROR		= 0x6002		# 命令：返回网关
ITMU_DELIVER	= 0x6003		# 命令：转移传送
ITMU_FORWARD	= 0x6004		# 命令：转发


#----------------------------------------------------------------------
# userver - 精简的stun服务器（负责转发和取nat）
# 原理很简单，只要实现ITMU_ECHO, ITMU_MIRROR, ITMU_FORWARD
# 三条消息，只需要在open以后不停的调用update方法即可
#----------------------------------------------------------------------
class userver(object):
	
	# 对象初始化
	def __init__ (self):
		self.state = -1
		self.sock = None
		self.port = -1
		self.time = time.time()
		self.errd = ( errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK )
		self.errs = ( 10054, 10053, 10035 )
	
	# 初始化：传入端口号
	def open (self, port = 0, bufsize = -1):
		self.close()
		if bufsize < 0: 
			bufsize = 0x100000
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsize)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)
		try: self.sock.bind(('0.0.0.0', port))
		except: 
			self.close()
			return -1
		self.sock.setblocking(0)
		self.port = self.sock.getsockname()[1]
		self.time = time.time()
		self.state = 0
		return 0
	
	# 关闭网络
	def close (self):
		if self.sock:
			try: self.sock.close()
			except: pass
			self.sock = None
		self.port = -1
		self.state = -1
	
	# 原始 UDP发送
	def __rawsend (self, data, remote):
		try:
			self.sock.sendto(data, remote)
		except socket.error,(code, strerror):
			pass
	
	# 原始 UDP接收
	def __rawrecv (self, size = 0x10000):
		try:
			data, remote = self.sock.recvfrom(size)
		except socket.error,(code, strerror):
			return '', None
		return data, remote
	
	# 处理 UDP消息
	def __process (self, data, remote):
		head = struct.unpack('<LLLL', data[:16])
		cmd = int(head[0] & 0x7fffffff)
		if cmd == ITMU_ECHO:			# 回射消息：ping
			self.__rawsend(data, remote)
		elif cmd == ITMU_MIRROR:		# 取nat地址
			sockaddr = 	'\x02\x00' + struct.pack('!H', remote[1])
			sockaddr += socket.inet_aton(remote[0]) 
			sockaddr += '\x00\x00\x00\x00\x00\x00\x00\x00'
			self.__rawsend(data[:16] + sockaddr, remote)
		elif cmd == ITMU_DELIVER:		# 转发：低版本
			val_ip = socket.inet_ntoa(data[4:8])
			val_port = struct.unpack('!H', data[12:14])[0]
			self.__rawsend(data[16:], (val_ip, val_port))
		elif cmd == ITMU_FORWARD:		# 转发：高版本（带源地址）
			val_ip = socket.inet_ntoa(data[4:8])
			val_port = struct.unpack('<H', data[12:14])[0]
			head = data[:4] + socket.inet_aton(remote[0])
			head += '\x00\x00\x00\x00'
			head += struct.pack('!H', remote[1]) + '\x00\x00'
			self.__rawsend(head + data[16:], (val_ip, val_port))
		return 0
	
	# 更新状态：需要不停的调用，比如1毫秒调用一次
	def update (self):
		self.time = time.time()
		if not self.sock:
			return -1
		while True:
			data, remote = self.__rawrecv()
			if remote == None: 
				break
			self.__process(data, remote)
		return 0


#----------------------------------------------------------------------
# udpnet - 带stun服务器转发功能的udp数据收发类
# 自动与上面的stun服务器连接并自动取得nat地址，在send/recv方法中
# 可以使用服务器转发这个功能 (forward = 1)
#----------------------------------------------------------------------
class udpnet(object):

	# 对象初始化
	def __init__ (self):
		self.state = -1
		self.sock = None
		self.port = -1
		self.sndque = collections.deque()
		self.rcvque = collections.deque()
		self.addr = []
		self.time = time.time()
		self.tm_active = time.time()
		self.tm_period = 0.3
		self.errd = ( errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK )
		self.errs = ( 10054, 10053, 10035 )
		self.server = None
		self.nat = None
		self.pingsvr = 500
		self.maxlen = 1024
		self.globalip = 0
		self.type = EP_NORMAL
		self.ep = endpoint()
		self.linkdesc = ''
		self.statistic_reset()
	
	# 统计数据复位
	def statistic_reset (self):
		self.statistic_packet_in = 0
		self.statistic_packet_out = 0
		self.statistic_data_in = 0
		self.statistic_data_out = 0
		self.statistic_packet_in_save = 0
		self.statistic_packet_out_save = 0
		self.statistic_data_in_save = 0
		self.statistic_data_out_save = 0
		self.statistic_packet_in_per_sec = 0
		self.statistic_packet_out_per_sec = 0
		self.statistic_data_in_per_sec = 0
		self.statistic_data_out_per_sec = 0
		self.statistic_time = time.time()
		self.statistic_startup = time.time()
	
	# 打开网络：需要指明端口和 stun服务器地址
	def open (self, port = 0, server = None, maxlen = 4000, bufsize = -1):
		self.close()
		if bufsize < 0: 
			bufsize = 0x100000
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsize)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)
		try: self.sock.bind(('0.0.0.0', port))
		except: 
			self.close()
			return -1
		self.sock.setblocking(0)
		self.port = self.sock.getsockname()[1]
		self.time = time.time()
		self.tm_active = self.time
		self.tm_period = 0.3
		self.state = 0
		self.server = server
		self.maxlen = maxlen
		self.ep = endpoint()
		self.__refresh_addr()
		return 0

	# 关闭网络
	def close (self):
		if self.sock:
			try: self.sock.close()
			except: pass
			self.sock = None
		self.port = -1
		self.state = -1
		self.sndque.clear()
		self.rcvque.clear()
		self.addr = []
		self.nat = None
		self.server = None
		self.globalip = 0
		self.linkdesc = ''
		self.pingsvr = 500
		self.statistic_reset()
		return 0
	
	# 原始 UDP发送
	def __rawsend (self, data, remote):
		try:
			self.sock.sendto(data, remote)
			self.statistic_packet_out += 1
			self.statistic_data_out += len(data)
		#except socket.error,(code, strerror):
		except:
			pass
	
	# 原始 UDP接收
	def __rawrecv (self, size = 0x10000):
		try:
			data, remote = self.sock.recvfrom(size)
			self.statistic_packet_in += 1
			self.statistic_data_in += len(data)
		#except socket.error,(code, strerror):
		except:
			return '', None
		return data, remote

	# 保活：定时保持和stun服务器的会话及 nat映射
	def __active (self):
		if self.time >= self.tm_active:
			if self.state == 0:
				self.tm_active = self.time + self.tm_period
				self.tm_period *= 1.3
				if self.tm_period >= 10:
					self.tm_period = 10
			else:
				self.tm_active = self.time + 5
			head = struct.pack('<HHLLL', ITMU_MIRROR, 0x8000, 0, 0, 0)
			if self.server:
				self.__rawsend(head, self.server)
			head = struct.pack('<HHLLL', ITMU_ECHO, 0x8000, 0, 0, 0)
			head += struct.pack('<L', _millisec())
			if self.server:
				self.__rawsend(head, self.server)
			self.__refresh_addr()
		return 0

	# 刷新地址：定时刷新本地地址列表
	def __refresh_addr (self):
		self.addr = hostaddr()			# 取得本地地址列表
		self.ep = endpoint()			# 创建 endpoint
		for ip, id in self.addr:		# 设置本地地址列表
			hostep = (ip, self.port)
			if hostep == self.nat:
				self.globalip = 1
			self.ep.local.append(hostep)	# 添加本地地址
		if self.nat:
			self.ep.nat = self.nat		# 添加 nat地址
		self.ep.analyse()
		self.type = self.ep.type
		self.linkdesc = self.ep.marshal()	# 更新链接描述
		if self.linkdesc == '':			# 没有地址时使用 127.0.0.1
			self.linkdesc = '127.0.0.1:%d'%(self.port)
		return 0
	
	# 尝试接收
	def __try_recv (self):
		data, remote = self.__rawrecv()
		if remote == None:
			return '', None, -1
		if remote != self.server:
			return data, remote, 0
		if len(data) < 16: 
			return '', None, 1
		head = struct.unpack('<LLLL', data[:16])
		body = data[16:]
		cmd = int(head[0] & 0x7fffffff)
		if cmd == ITMU_MIRROR:		# 取得nat地址
			val_ip = socket.inet_ntoa(data[20:24])
			val_port = struct.unpack('!H', data[18:20])[0]
			self.nat = (val_ip, val_port)
			if self.state == 0:
				self.state = 1
			self.__refresh_addr()
			self.tm_active = self.time + 45
			return '', None, 1
		elif cmd == ITMU_ECHO:		# 返回到stun服务器的ping值
			oldtime = struct.unpack('<L', body[:4])[0]
			current = _millisec()
			if current > oldtime: 
				self.pingsvr = current - oldtime
			self.tm_active = self.time + 45
			return '', None, 1
		elif cmd == ITMU_FORWARD:	# stun服务器转发来的消息
			val_ip = socket.inet_ntoa(data[4:8])
			val_port = struct.unpack('!H', data[12:14])[0]
			remote = (val_ip, val_port)
			return body, remote, 1
		return '', None, 1

	# 更新统计状态
	def statistic_update (self):
		if self.time - self.statistic_time < 1.0:
			return 0
		delta = self.time - self.statistic_time
		self.statistic_time = self.time
		p_in = self.statistic_packet_in - self.statistic_packet_in_save
		p_out = self.statistic_packet_out - self.statistic_packet_out_save
		d_in = self.statistic_data_in - self.statistic_data_in_save
		d_out = self.statistic_data_out - self.statistic_data_out_save
		self.statistic_packet_in_save = self.statistic_packet_in
		self.statistic_packet_out_save = self.statistic_packet_out
		self.statistic_data_in_save = self.statistic_data_in
		self.statistic_data_out_save = self.statistic_data_out
		self.statistic_packet_in_per_sec = p_in / delta
		self.statistic_packet_out_per_sec = p_out / delta
		self.statistic_data_in_per_sec = d_in / delta
		self.statistic_data_out_per_sec = d_out / delta
		return 0
	
	# 生成统计文本
	def statistic_report (self):
		text = 'statistic: '
		text += 'time=%d '%(int(self.time - self.statistic_startup))
		text += 'packet_in=%d '%self.statistic_packet_in
		text += 'packet_out=%d '%self.statistic_packet_out
		text += 'data_in=%d '%self.statistic_data_in
		text += 'data_out=%d '%self.statistic_data_out
		return text

	# 更新状态：需要不停调用，比如1毫秒一次
	def update (self):
		self.time = time.time()
		if not self.sock:
			return -1
		self.__active()
		while 1:
			data, remote, mode = self.__try_recv()
			if remote != None:
				if len(self.rcvque) < self.maxlen:
					self.rcvque.append((data, remote, mode))
			elif mode == -1:
				break
		self.statistic_update()
		return self.state
	
	# 发送数据：data:数据  remote:远程地址  forward:是否用stun服务器转发
	def send (self, data, remote, forward = 0):
		if not forward:
			self.__rawsend(data, remote)
		elif self.server:
			head = struct.pack('<HH', ITMU_FORWARD, 0x8000)
			val_ip = struct.unpack('<L', socket.inet_aton(remote[0]))[0]
			val_port = remote[1]
			head += struct.pack('<LLL', val_ip, 0, val_port)
			self.__rawsend(head + data, self.server)

	# 接收数据：data:数据  remote:远程地址  forward:是否从stun服务器转发
	def recv (self):
		if len(self.rcvque) == 0:
			return '', None, -1
		data, remote, mode = self.rcvque.popleft()
		return data, remote, mode


#----------------------------------------------------------------------
# address operation
#----------------------------------------------------------------------
def packaddr(remote):
	return socket.inet_aton(remote[0]) + struct.pack('!H', remote[1])

def unpackaddr(str):
	ip = socket.inet_ntoa(str[:4])
	port = struct.unpack('!H', str[4:6])
	return (ip, port)


#----------------------------------------------------------------------
# 超时控制：比较是否超时
#----------------------------------------------------------------------
class timeout(object):

	# 对象初始化：设置当前时间，初始周期，还有周期扩大因子
	def __init__ (self, current = -1, period = 0.3, multiplier = 1.2):
		if current < 0:
			current = time.time()
		self.base = float(current)
		self.period = float(period)
		self.rto = self.period
		self.multiplier = multiplier
		self.startup = self.base
		self.init = 0

	# 检查是否超时：超时的话返回True，并增加周期
	def check (self, current = -1):
		if current < 0:
			current = time.time()
		current = float(current)
		if self.init == 0:
			self.init = 1
			return True
		if self.base + self.rto > current:
			return False
		self.base = current
		self.rto *= self.multiplier
		return True

	# 复位：复位超时周期 
	def reset (self, current = -1):
		if current < 0:
			current = time.time()
		current = float(current)
		self.base = current
		self.rto = self.period
		self.startup = self.base
		self.init = 0
	
	# 检查上一次 reset到现在的时间
	def last (self, current = -1):
		if current < 0:
			current = time.time()
		current = float(current)
		return current - self.startup


#----------------------------------------------------------------------
# 连接分析: 比较可以连接的地址
#----------------------------------------------------------------------
def analyse_endpoints(ep_local, ep_remote):
	available = endpoint()

	if ep_remote.type == EP_GLOBAL:
		available.local.append(ep_remote.nat)
	
	local = False

	if ep_local.nat and ep_remote.nat:
		available.nat = ep_remote.nat
		if ep_remote.nat[0] == ep_local.nat[0]:
			local = True
	
	elif ep_local.nat == None or ep_remote.nat == None:
		local = True
	
	if local:
		for remote in ep_remote.local:
			matchip = False
			for ip, port in ep_local.local:
				iphead1 = '.'.join(ip.split('.')[:2])
				iphead2 = '.'.join(remote[0].split('.')[:2])
				if iphead1 == iphead2:
					matchip = True
					break
			if matchip:
				available.local.append(remote)

	available.localhost = False

	if available.nat == None and len(available.local) == 0:
		match = True
		if ep_local.nat != ep_remote.nat:
			match = False
		elif len(ep_local.local) != len(ep_remote.local):
			match = False
		else:
			for i in xrange(len(ep_local.local)):
				if ep_local.local[i] != ep_remote.local[i]:
					match = False
					break
		available.localhost = match

	return available


#----------------------------------------------------------------------
# 连接求解: 取得可以用于连接的地址
#----------------------------------------------------------------------
def destination(ep, extadd = None, extway = -1):
	final = []
	extra = []
	for remote in ep.local:
		extra.append((remote, 0))
	if ep.nat:
		extra.append((ep.nat, 1))
		extra.append((ep.nat, 0))
	if extadd and extway >= 0:
		extra.append((extadd, extway))
	for remote, forward in extra:
		findok = False
		for dstadd, dstway in final:
			if dstadd == remote and dstway == forward:
				findok = True
				break
		if not findok:
			final.append((remote, forward))
	extra = []
	return final


#----------------------------------------------------------------------
# 地址类型识别：用于优先选择局域网地址（返回值越小越好）
#----------------------------------------------------------------------
def iptype(ip):
	f = lambda a: socket.inet_aton(a)
	a = f(ip)
	if a == f('127.0.0.1'):
		return 0
	if (a >= f('192.168.0.0') and a <= f('192.168.255.255')):
		return 1
	if (a >= f('10.0.0.0') and a <= f('10.255.255.255')): 
		return 2
	if (a >= f('172.16.0.0') and a <= f('172.31.255.255')):
		return 3
	return 10


#----------------------------------------------------------------------
# testing case
#----------------------------------------------------------------------
if __name__ == '__main__':
	print 'testing', hostname

	def test1():
		print '-' * 70
		addr = hostaddr()
		ep = endpoint([ (n[0], 12) for n in hostaddr() ], ('218.107.55.250', 3000))
		print ep.marshal(), ep.type
		e2 = endpoint().unmarshal(ep.text)
		print e2.marshal(), e2.type
		print '-' * 70
		print text2ep('192.168.1.10:3333')
		print socket.inet_ntoa(socket.inet_aton('192.168.1.1'))
		print repr(socket.inet_aton('192.168.1.1'))

	def test2():
		host = udpnet()
		for n in hostaddr(): print n
		server = ('218.107.55.250', 6000)
		server = ('218.107.55.250', 2009)
		host.open(0, server)
		while 1:
			if host.update() == 1: break
			time.sleep(1)
		print 'nat at', host.nat, 'type', host.type
		#raw_input()
		for i in xrange(2):
			host.send('HHHH', host.nat, 1)
			host.send('HHHH', host.nat, 0)
		while 1:
			time.sleep(0.1)
			host.update()
			data, remote, mode = host.recv()
			if remote or mode >= 0:
				print data, remote, mode

	def test3():
		host = udpnet()
		udpsvr = userver()
		udpsvr.open(6000)
		server = ('127.0.0.1', 6000)
		host.open(0, server)
		while 1:
			if host.update() == 1: break
			udpsvr.update()
			time.sleep(1)
		print 'nat at', host.nat, 'type', host.type
		#raw_input()
		for i in xrange(2):
			host.send('HHHH', host.nat, 1)
			host.send('HHHH', host.nat, 0)
		while 1:
			time.sleep(0.1)
			host.update()
			udpsvr.update()
			data, remote, mode = host.recv()
			if remote or mode >= 0:
				print data, remote, mode

	def test4():
		local1 = [ ('192.168.1.2', 3000), ('10.0.0.2', 3000) ]
		local2 = [ ('172.16.0.2', 4000), ('192.168.20.2', 4000) ]
		local3 = [ ('218.107.55.250', 5000), ('192.168.2.4', 1234) ]
		local4 = [ ('10.2.2.2', 4312) ]
		ep1 = endpoint(local1, ('218.107.55.254', 1234))
		ep2 = endpoint(local2, ('218.107.55.254', 4321))
		ep3 = endpoint(local3, ('218.107.55.250', 5000))
		ep4 = endpoint(local4, ('202.108.8.44', 2233))
		def cmp(e1, e2):
			print 'src:', e1.marshal()
			print 'dst:', e2.marshal()
			e = analyse_endpoints(e1, e2)
			print 'link:', e.marshal()
			print 'localhost:', e.localhost
			print ''
		cmp(ep1, ep2)
		cmp(ep1, ep3)
		cmp(ep2, ep3)
		cmp(ep2, ep4)
		cmp(endpoint(), endpoint())
		print endpoint().unmarshal('127.0.0.1:6766').marshal()
		print repr(endpoint().marshal())
		return 0
	
	def test5():
		tm1 = timeout()
		startup = time.time()
		while 1:
			time.sleep(0.1)
			if tm1.check():
				print 'timeout tm=%.3f rto=%.3f'%(time.time() - startup, tm1.rto)
			if tm1.rto >= 5.0:
				tm1.reset()
				startup = time.time()
				print 'reset\n'
	test3()


