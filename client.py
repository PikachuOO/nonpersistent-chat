#!/usr/bin/python 

import socket, sys, struct, time, threading, thread
from socket import error as socket_error

# connect socket to where server is listening
SERVERHOST = sys.argv[1]
SERVERPORT = int(sys.argv[2])
CLIENTHOST = sys.argv[3]
CLIENTPORT = int(sys.argv[4])
auth_username = ''
auth_token = ''
auth_tuple = ''
known_users = dict()

def main():
	listen_thread = threading.Thread(target=listen, args=(CLIENTHOST, CLIENTPORT))
	listen_thread.daemon = True
	listen_thread.start()
	login()
	pulse_thread = threading.Thread(target=pulse)
	pulse_thread.daemon = True
	pulse_thread.start()
	while True:
		command = raw_input()
		command_parts = command.partition(" ")
		first_word = command_parts[0]
		next_word = command_parts[2]
		# message
		if first_word == 'message':
			args = next_word.split(None, 1)
			target_user = args[0]
			message = args[1]
			send_message_through_server(target_user, message)

		# broadcast
		if first_word == 'broadcast':
			message = next_word
			broadcast(message)

		# online
		if first_word == 'online':
			fetch_users()

		# block
		if first_word == 'block':
			target_user = next_word
			toggle_blocking(1, target_user)

		# unblock
		if first_word == 'unblock':
			target_user = next_word
			toggle_blocking(0, target_user)

		# logout
		if first_word == 'logout':
			logout()

		# getaddress
		if first_word == 'getaddress':
			target_user = next_word
			get_address(target_user)

		if first_word == 'allow':
			target_user = next_word
			give_address_to(target_user)

		# private
		if first_word == 'private':
			args = next_word.split(None, 1)
			target_user = args[0]
			message = args[1]
			private_message(target_user, message)
'''
INVOLUNTARY ACTIONS
'''
# as in heartbeat, i guess
def pulse():
	while 1:
		time.sleep(20.0)
		tell_server('HEY|' + auth_tuple)

# prompts user to log in. once logged in the username is saved.
def login():
	serversock = socket.socket()
	serversock.connect((SERVERHOST, SERVERPORT))
	send_message(serversock, 'LIN')

	logged_in = False
	while not logged_in:
		username = raw_input('Username: ')
		password = raw_input('Password: ')
		send_message(serversock, username)
		send_message(serversock, password)
		response = recv_message(serversock)
		if response == 'LOGIN_OKAY':
			logged_in = True
			print 'Welcome,', username, '!'
		else:
			r = response.split('|')
			if r[0] == 'PENNED':
				print username, 'is suspended for another', r[1], 'seconds.'
			if r[0] == 'JUST_PENNED':
				print 'Too many login attempts. Please wait', r[1], 'seconds.'
			if r[0] == 'LOGIN_FAILED':
				print 'Incorrect username/password.', r[1], 'more login attempts.'
	global auth_username
	auth_username = username
	global auth_token
	auth_token = recv_message(serversock)
	global auth_tuple
	auth_tuple = auth_username + '|' + auth_token + '|'
	send_message(serversock, CLIENTHOST)
	send_message(serversock, str(CLIENTPORT))
			
	serversock.close()

# always be listening
def listen(host, port):
	clientsock = socket.socket()
	clientsock.bind((host, port))
	clientsock.listen(5)
	while 1:
		conn, client_addr = clientsock.accept()
		received = recv_message(conn)
		if received[:3] == 'ADR':
			save_address(received)
		else:
			print received
		conn.close()

'''
VOLUNTARY ACTIONS
'''

def send_message_through_server(target_user, message):
	tell_server('MSG|' + auth_tuple + target_user + '|' + message)

# tell server to broadcast
def broadcast(message):
	tell_server('BRD|' + auth_tuple + message)

# fetch active users from server
def fetch_users():
	tell_server('ONL|' + auth_tuple)

def toggle_blocking(should_block, username):
	tell_server('BLC|' + auth_tuple + str(should_block) + '|' + username)

# tell server logout
def logout():
	tell_server('OUT|' + auth_tuple)
	sys.exit(1)

def get_address(username):
	serversock = socket.socket()
	serversock.connect((SERVERHOST, SERVERPORT))
	send_message(serversock, 'GET|' + auth_tuple + username)
	response = recv_message(serversock)
	if response == 'OKAY':
		print 'Request has been sent.'
	else:
		print username, ' cannot be found'
	serversock.close()

def give_address_to(username):
	tell_server('ALL|' + auth_tuple + username)

def save_address(data):
	d = data.split('|')
	new_name = d[1]
	new_host = d[2]
	new_port = d[3]
	known_users[new_name] = (new_host, int(new_port))
	print 'You can now privately message', new_name

def private_message(username, message):
	edited_message = '<' + auth_username + '>: ' + message
	try:
		if username in known_users:
			peersock = socket.socket()
			peersock.connect(known_users[username])
			send_message(peersock, edited_message)
			peersock.close()
		else:
			print "I don't yet know who ", username, " is."
	except socket_error:
		print username, "is no longer online."


'''
others
'''
# sending things to server without waiting for a response
def tell_server(message):
	serversock = socket.socket()
	serversock.connect((SERVERHOST, SERVERPORT))
	send_message(serversock, message)
	serversock.close()

# three methods to encapsulate sending/receiving data
def send_message(sock, data):
	message_length = len(data)
	sock.sendall(struct.pack('!I', message_length))
	sock.sendall(data)

def recv_message(sock):
	message_length_buffer = recvall(sock, 4)
	message_length, = struct.unpack('!I', message_length_buffer)
	return recvall(sock, message_length)

def recvall(sock, count):
	data = b''
	while count:
		temp = sock.recv(count)
		if not temp: return None
		data += temp
		count -= len(temp)
		return data

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print 'goodbye!'
	sys.exit(1)