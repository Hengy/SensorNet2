import socket, struct, sys, time

message = 'SensorNet_Discover_Node:192.168.0.104:31416'
multicast_addr = ('239.255.0.1', 31415)
resp_addr = ('192.168.0.104',31416)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)		# UDP send socket
sock_resp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# UDP receive socket

sock_resp.settimeout(2)

ttl = struct.pack('b',1)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

sock_resp.bind(('',31416))

try:
	print "Sending: {0}".format(message)
	sent = sock.sendto(message, multicast_addr)
	
	while True:
		print "waiting..."
		try:
			data, server = sock_resp.recvfrom(1024)
		except socket.timeout:
			print "Timeout. No responses."
			break
		else:
			print "Recieved \"{0}\" from {1}".format(data, server)

	msg = str(data)

	sensornet_ip = msg[msg.find(':')+1 : msg.find(':',26)]
	print 'IP: ' + sensornet_ip
	sensornet_port = msg[msg.find(':',26)+1 : len(msg)]
	print 'PORT: ' + sensornet_port

	server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_sock.connect((sensornet_ip, int(sensornet_port)))

	server_sock.sendall('sensor data...')

	server_sock.close()

	time.sleep(1)

	message = 'Kill31415'

	print 'Sending: {0}'.format(message)

	sent = sock.sendto(message, multicast_addr)

finally:
	print "Closing..."
	sock.close()
	sock_resp.close()
