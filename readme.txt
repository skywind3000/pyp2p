1. start test_stun_server.py
2. change STUN_SERVER in test_p2p_clients.py
3. start test_p2p_clients.py

use easenet.send(ident1, ident2, channel, data)

to send data: channel=0 (reliable data) channel1 (un-reliable data)

use easenet.recv(ident1, ident2)

to receive data