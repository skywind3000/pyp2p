#! /usr/bin/env python
# -*- coding: utf-8 -*-
#======================================================================
#
# cnetdat.py - simple reliable data protocol (no congestion control)
#
# NOTE:
# for more information, please see the readme file.
# 
#======================================================================
import sys
import time
import struct
import collections



#----------------------------------------------------------------------
# global definition
#----------------------------------------------------------------------
SEG_DAT		= 0x5000
SEG_ACK		= 0x5001

#----------------------------------------------------------------------
# segment - 数据段落
#----------------------------------------------------------------------
class segment(object):
	def __init__ (self, conv = 0, cmd = SEG_DAT, seq = 0, ts = 0, data = ''):
		self.conv = conv
		self.cmd = cmd
		self.seq = seq
		self.ts = ts
		self.data = data
		self.raw = ''
	def marshal (self):
		text = struct.pack('!LLLL', self.conv, self.cmd, self.seq, self.ts)
		self.raw = text + self.data
		return self.raw
	def unmarshal (self, text):
		if len(text) < 16:
			raise Exception('format error')
		record = struct.unpack('!LLLL', text[:16])
		self.conv = record[0]
		self.cmd = record[1]
		self.seq = record[2]
		self.ts = record[3]
		self.data = text[16:]
		return self


#----------------------------------------------------------------------
# reliable - 协议制定
#----------------------------------------------------------------------
class reliable(object):
	
	def __init__ (self, conv, mtu = 1400, current = -1, id = 0):
		self.conv = conv
		self.snd_una = 0
		self.snd_nxt = 0
		self.rcv_nxt = 0
		self.ts_recent = 0
		self.ts_lastack = 0
		self.rx_rttval = 0
		self.rx_srtt = 0
		self.rx_rto = 300
		self.rx_minrto = 10
		self.snd_wnd = 64
		self.rcv_wnd = 64
		self.snd_buf = {}
		self.rcv_buf = {}
		self.ack_lst = []
		self.mtu = mtu
		self.mss = self.mtu - 20
		self.sendque = collections.deque()
		self.recvque = collections.deque()
		if current < 0: 
			current = time.time()
		self.current = current
		self.timestamp = long(current * 1000) & 0xffffffff
		self.id = id
		self.state = 0

	def send (self, data):
		self.sendque.append(data)
	
	def recv (self):
		if len(self.recvque) == 0:
			return None
		return self.recvque.popleft()
	
	# 数据输出：外部实现
	def output (self, data):
		return 0

	# 数据输入：外部调用
	def input (self, data):
		if data[:4] != 'CNET':
			return -1
		pos = 4
		retval = 0
		while pos < len(data):				# 分解数据
			head = data[pos:pos + 2]
			if len(head) < 2:
				break
			size = struct.unpack('!H', head)[0]
			#print 'size=', size, pos
			text = data[pos + 2:pos + 2 + size]
			pos += 2 + size
			if size != len(text):
				retval = -2
				break
			try:							# 数据解包
				seg = segment().unmarshal(text)
			except: 
				retval = -3
				break
			if seg.conv != self.conv:
				retval = -4
				break
			self.log('parse %d: size %d'%(seg.cmd, len(text)))
			if seg.cmd == SEG_DAT:
				self._parse_dat(seg)		# 解析输入数据
			elif seg.cmd == SEG_ACK:
				self._parse_ack(seg)		# 解析输入响应
		return retval

	# 处理缓存：将发送缓存中可以发送的数据output出去
	def flush (self):
		current = self.current
		timestamp = self.timestamp
		text = ''
		self.ack_lst.sort()							# 发送响应
		for seq, ts in self.ack_lst:
			seg = segment(self.conv, SEG_ACK, seq, ts)
			data = seg.marshal()
			text += struct.pack('!H', len(data)) + data
			if len(text) + 16 >= self.mss:
				self.output('CNET' + text)
				text = ''
		self.ack_lst = []
		while self.snd_nxt < self.snd_una + self.snd_wnd:	# 复制数据岛缓存
			if len(self.sendque) == 0:
				break
			data = self.sendque.popleft()
			seg = segment(self.conv, SEG_DAT, self.snd_nxt, 0, data)
			seg.ts_resend = current					# 设置新的 segment
			seg.ts = timestamp
			seg.data = data
			seg.xmit = 0
			seg.enlarge = 1.0
			self.snd_buf[self.snd_nxt] = seg
			self.snd_nxt += 1						# 序列号增加
		queue = []
		for seq in self.snd_buf:
			seg = self.snd_buf[seq]
			if current >= seg.ts_resend:
				queue.append((seq, seg))
		queue.sort()
		for seq, seg in queue:						# 组装发送
			seg.ts = timestamp
			seg.ts_resend = current + seg.enlarge * self.rx_rto * 0.001
			seg.enlarge *= 1.2
			seg.xmit += 1
			if seg.xmit >= 10:
				self.state = -1
			data = seg.marshal()
			if len(data) + len(text) >= self.mss:
				self.output('CNET' + text)
				text = ''
			text += struct.pack('!H', len(data)) + data
		if text != '':								# 输出末尾
			self.output('CNET' + text)
		queue = None
		return 0
	
	# 解析输入：分析单个输入的 SEG_DAT
	def _parse_dat (self, seg):
		self.log('<data seq=%d ts=%d size=%d>'%(seg.seq, seg.ts, len(seg.data)))
		if seg.seq >= self.rcv_nxt + self.rcv_wnd:
			return -1
		current = self.current
		timestamp = self.timestamp
		self.ack_lst.append((seg.seq, seg.ts))
		if (not seg.seq in self.rcv_buf) and (seg.seq >= self.rcv_nxt):
			self.rcv_buf[seg.seq] = seg
		while True:							# 将准备好的数据移动到recvque
			if not self.rcv_nxt in self.rcv_buf:
				break
			seg = self.rcv_buf[self.rcv_nxt]
			self.recvque.append(seg.data)
			self.log('putin', len(self.recvque))
			del self.rcv_buf[self.rcv_nxt]
			self.rcv_nxt += 1
		return 0
	
	# 解析输入：分析单个输入的 SEG_ACK
	def _parse_ack (self, seg):
		current = self.current
		timestamp = self.timestamp
		if seg.ts < timestamp:				# 更新超时
			rtt = timestamp - seg.ts
			if self.rx_srtt == 0:
				self.rx_srtt = rtt
				self.rx_rttval = rtt / 2
			else:
				delta = rtt - self.rx_srtt
				if delta < 0: delta = -delta
				self.rx_rttval = (3 * self.rx_rttval + delta) / 4
				self.rx_srtt = (7 * self.rx_srtt + rtt) / 8
			rto = self.rx_srtt + max(1, 2 * self.rx_rttval)
			if rto > 10000: rto = 10000
			if rto <= 1: rto = 1
			self.rx_rto = rto
			#print 'rtt=%d rto=%d'%(rtt, rto)
		if not seg.seq in self.snd_buf:
			return 0
		del self.snd_buf[seg.seq]			# 更新发送缓存
		while self.snd_una <= self.snd_nxt:
			if self.snd_una in self.snd_buf:
				break
			self.snd_una += 1
		return 0
	
	def log (self, *args):
		head = time.strftime('%H:%M:%S', time.localtime())
		tail = ' '.join([ str(n) for n in args ])
		text = '[%s] [%d] %s'%(head, self.id, tail)
		#print text

	# 更新时钟
	def update (self, current = -1):
		if current < 0:
			current = time.time()
		self.current = current
		self.timestamp = long(current * 1000) & 0xffffffff
		self.flush()
		
	


#----------------------------------------------------------------------
# simulator - 网络模拟
#----------------------------------------------------------------------
class simpipe(object):
	def __init__ (self, rtt = 0.2, lost = 0.1, amb = 0.5, limit = 100):
		self.pipe = []
		self.limit = limit
		self.rtt = rtt * 0.5
		self.lost = lost
		self.amb = amb
		self.wave = self.rtt * self.amb
	def put (self, data):	# 插入数据并加上一个随机延迟
		current = time.time()
		import random
		if random.random() <= self.lost:
			return 1
		wave = self.rtt + self.wave * (2 * random.random() - 1)
		future = wave < 0.0 and current or (current + wave)
		if len(self.pipe) >= self.limit:
			return -1
		self.pipe.append((future, str(data)))
		self.pipe.sort()
		return 0
	def get (self):			# 取得到时间的消息
		current = time.time()
		if len(self.pipe) == 0: 
			return None
		if current < self.pipe[0][0]:
			return None
		data = self.pipe[0][1]
		self.pipe = self.pipe[1:]
		return data

class simnet(object):
	def __init__ (self, input, output):
		self.input = input
		self.output = output
	def send (self, data):
		self.output.put(data)
	def recv (self):
		data = self.input.get()
		if data == None:
			return ''
		return data

def simulator(rtt = 0.2, lost = 0.1, amb = 0.5, limit = 100):
	pipe1 = simpipe(rtt, lost, amb, limit)
	pipe2 = simpipe(rtt, lost, amb, limit)
	p1 = simnet(pipe1, pipe2)
	p2 = simnet(pipe2, pipe1)
	return p1, p2


#----------------------------------------------------------------------
# tester
#----------------------------------------------------------------------
class netreliable(reliable):
	def __init__ (self, conv, mtu = 1400, current = -1, id = 0, \
				network = None):
		super(netreliable, self).__init__ (conv, mtu, current, id)
		self.network = network
	def output (self, data):
		if self.network:
			self.network.send(data)
	def update2 (self, current = -1):
		if self.network:
			while 1:
				data = self.network.recv()
				if data == '': break
				self.input(data)
		super(netreliable, self).update(current)
		return 0


#----------------------------------------------------------------------
# testing case
#----------------------------------------------------------------------
if __name__ == '__main__':
	def test1():
		p1, p2 = simulator()
		for i in xrange(100):
			p1.send(str(i))
			print 'put', i
			time.sleep(0.05)
		segment().unmarshal(segment().marshal())
		while 1:
			data = p2.recv()
			if data != '':
				print 'get', data
			time.sleep(0.1)
	def test2():
		p1, p2 = simulator()		# 虚拟网络
		n1 = netreliable(1234, network = p1, id = 1)
		n2 = netreliable(1234, network = p2, id = 2)
		index = 0
		time_slap = time.time() + 1.0
		while 1:
			time.sleep(0.001)
			n1.update2()
			n2.update2()
			if time.time() >= time_slap:	# 客户1发送
				time_slap = time.time() + 0.01
				n1.send('snd_%d %.4f'%(index, time.time()))
				index += 1
			while 1:						# 客户2回射
				data = n2.recv()
				if data == None: break
				n2.send(data)
			while 1:						# 客户1显示
				data = n1.recv()
				if not data: break
				record = data.split(' ')
				ts = time.time() - float(record[1])
				print '[RECV]', record[0], ts
	test2()
	

	