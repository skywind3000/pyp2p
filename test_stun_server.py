import sys, time
import cnetudp


def running():
	stun = cnetudp.userver()
	stun.open(9000)
	print 'stun server startup (listening from port 9000) ....'
	while 1:	
		stun.update()
		time.sleep(0.002)


if __name__ == '__main__':
	running()
