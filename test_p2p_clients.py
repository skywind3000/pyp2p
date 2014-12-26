import sys, time
import easenet

# stun server (punching server) address
STUN_ADDRESS = ('127.0.0.1', 9000)


# wait peers to login (punching ok)
def wait(*args):
	timeout = time.time() + 4
	while 1:
		time.sleep(0.05)
		count = 0
		for host in args:
			host.update()
			if host.login() == 1:
				count += 1
		if count == len(args): 
			break
		if time.time() > timeout: break
	return 0


# testing p2p
def test_p2p_client(uid1, key1, uid2, key2, STUN_SERVER):
	host1 = easenet.easenet()
	host2 = easenet.easenet()
	host1.init(uid1, key1, 0, STUN_SERVER)
	host2.init(uid2, key2, 0, STUN_SERVER)
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



#----------------------------------------------------------------------
# testing case
#----------------------------------------------------------------------
if __name__ == '__main__':
	# you need start stun server (test_stun_server.py)
	# and change STUN_ADDRESS
	test_p2p_client(20013080, 123, 20013070, 456, STUN_ADDRESS)


