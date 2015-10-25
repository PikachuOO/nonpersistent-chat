#!/usr/bin/python     
#!/usr/bin/python 

import socket
import sys
import struct
import thread
import threading
import time
import hashlib
from socket import error as socket_error
 

'''
timeouts
'''
LOGIN_FAILED_TIMEOUT = 60.0
CLIENT_LIFE = 30.0

# host = socket.gethostname()
host = sys.argv[1]
port = int(sys.argv[2])

# <username, token>
auth_table = dict()

# <username, timestamp of last heartbeat>
online_users = dict()

# <username, (host, port)>
user_directory = dict()

# <username, [blocked users]>
block_directory = dict()

# <username, [offline messages]>
offline_messages = dict()

# <username, failed login attempts since last unpenning>
failed_logins = dict()

# <username, time of last penning>
penned_users = dict()

def handler(conn, addr):
	command = recv_message(conn)
	c = command.split('|')
	if c[0] == 'LIN':
		login(conn, addr)
	else:
		username = c[1]
		token = c[2]
		if is_authenticated(username, token):
			if c[0] == 'MSG':
				from_username = c[1]
				to_username = c[3]
				message = c[4]
				relay_message(from_username, to_username, message)

			if c[0] == 'BRD':
				from_username = c[1]
				message = c[3]
				broadcast(from_username, message)

			if c[0] == 'ONL':
				from_username = c[1]
				display_online_users(from_username)

			if c[0] == 'BLC':
				blocker = c[1]
				mode = int(c[3])
				blockee = c[4]
				toggle_block(mode, blocker, blockee)

			if c[0] == 'OUT':
				from_username = c[1]
				logout(from_username)

			if c[0] == 'GET':
				requesting_user = c[1]
				requested_user = c[3]
				evaluated_address_request(conn, requesting_user, requested_user)

			if c[0] == 'ALL':
				requested_user = c[1]
				requesting_user = c[3]
				give_address(requesting_user, requested_user)

			if c[0] == 'HEY':
				username = c[1]
				refresh(username)
		else:
			print 'not real'

	conn.close()

def login(conn, addr):
	username, password = '', ''
	logged_in = False
	while not logged_in:
		username = recv_message(conn)
		password = recv_message(conn)
		if creds.get(username) == password and not is_penned(username):
			send_message(conn, 'LOGIN_OKAY')
			logged_in = True
			break
		elif is_penned(username):
			time_left_until_unpenned = str(how_long_until_unpenned(username))
			send_message(conn, 'PENNED|' + time_left_until_unpenned)
		else:
			count_failed_login_attempt(username)
			if is_penned(username):
				time_left_until_unpenned = str(how_long_until_unpenned(username))
				send_message(conn, 'JUST_PENNED|' + time_left_until_unpenned)
			else:
				tries_until_pen = str(how_many_tries_left(username))
				send_message(conn, 'LOGIN_FAILED|' + tries_until_pen)
	
	# generate a token
	t = hashlib.sha1()
	t.update(str(time.time()))
	token = t.hexdigest()[:10]
	send_message(conn, token)
	client_host = recv_message(conn)
	client_port = recv_message(conn)

	# save this user
	save_user(username, token, client_host, client_port)

	# send offline messages
	if username in offline_messages:
		send_offline_messages_to(username)

	# broadcast new person's presence
	tell_everyone(username, username + ' has logged on.')
	
# remember a user who has just logged in
def save_user(username, token, host, port):
	if username in online_users:
		tell_user(username, 'Logged on different location!')
	user_directory[username] = (host, int(port))
	online_users[username] = time.time()
	auth_table[username] = token

# increment count when user fails login
def count_failed_login_attempt(username):
	if username in failed_logins:
		tries = failed_logins[username]
		failed_logins[username] = tries + 1
	else:
		failed_logins[username] = 1
	if failed_logins[username] == 3:
		penned_users[username] = time.time()
		failed_logins[username] = 0

# fetch how many login attempts username has left
def how_many_tries_left(username):
	if username in failed_logins:
		return 3 - failed_logins[username]
	else:
		return 3

# see whether this username is currently penned
def is_penned(username):
	if username not in penned_users:
		return False
	else:
		now = time.time()
		if now - penned_users[username] > LOGIN_FAILED_TIMEOUT:
			return False
		else:
			return True

# returns how long the user has to wait before they can log in again
def how_long_until_unpenned(username):
	if username not in penned_users:
		return 0.0
	else:
		time_left = LOGIN_FAILED_TIMEOUT - (time.time() - penned_users[username])
		if time_left < 0:
			return 0.0
		else:
			return time_left

# sends a list of messages that were directed to the user when they were offline
def send_offline_messages_to(username):
	unread_messages = offline_messages[username]
	all_messages = 'While you were away...\n'
	for i in unread_messages:
		all_messages += i
	tell_user(username, all_messages)
	del unread_messages[:]
	del offline_messages[username]

# verifies the user has an active token
def is_authenticated(username, token):
	if username in auth_table:
		if auth_table[username] == token:
			return True
		else:
			return False
	else:
		return False

# handles sending a message through the message center
def relay_message(from_username, to_username, message):
	edited_message = '[' + from_username + ']: ' + message
	if has_blocked(to_username, from_username):
		tell_user(from_username, 'Your message could not be delivered as the recipient has blocked you.')
	else:
		if to_username in online_users:
			tell_user(to_username, edited_message)
		else:
			tell_user(from_username, 'The recipient is offline. Messages will be delivered when they log on again.')
			save_offline_message(to_username, edited_message)

# saves an offline message.
def save_offline_message(to_username, message):
	if to_username in offline_messages:
		current_list = offline_messages[to_username]
		current_list.append(message + '\n')
	else:
		offline_messages[to_username] = [message]

# message center tells something to a single user
def tell_user(username, message):
	try:
		sock = socket.socket()
		sock.connect(user_directory[username])
		send_message(sock, message)
		sock.close()
	except socket_error:
		save_offline_message(username, message)

# format "broadcast" messages, then call tell_everyone
def broadcast(from_username, message):
	edited_message = '[' + from_username + ']: ' + message
	tell_everyone(from_username, edited_message)

# sends a message to everyone
def tell_everyone(from_username, message):
	for key in online_users:
		if has_blocked(key, from_username):
			tell_user(from_username, 'Your message could not be delivered to some recipients.')
		else:
			tell_user(key, message)

# fetches the list of online users and sends them to the user who requested it
def display_online_users(username):
	userlist = '[CURRENTLY ONLINE]: '
	for key in online_users:
		userlist += key
		userlist += ' '
	tell_user(username, userlist)

# change a user's blocked/unblocked status
def toggle_block(mode, blocker, blockee):
	if blocker in block_directory:
		current_list = block_directory[blocker]
		if mode == 1:
			current_list.append(blockee)
			tell_user(blocker, 'You have blocked ' + blockee)
		if mode == 0 and blockee in current_list:
			current_list.remove(blockee)
			tell_user(blocker, 'You have unblocked ' + blockee)
	else:
		if mode == 1:
			block_directory[blocker] = [blockee]

# remove a user from online_users, and tell everyone
def logout(username):
	del online_users[username]
	tell_everyone(username, username + ' is offline.')

# once an address request is received, first check to see whether user is blocked
# then check if that user is online
# send a request for consent to that user if online and the requester is not blocked
# otherwise, fail the request
def evaluated_address_request(conn, requesting_user, requested_user):
	if requested_user in online_users and not has_blocked(requested_user, requesting_user):
		seek_address_consent(requesting_user, requested_user)
		send_message(conn, 'OKAY')
	else:
		send_message(conn, 'FAIL')

# asks requested user for their address
def seek_address_consent(requesting_user, requested_user):
	sock = socket.socket()
	sock.connect(user_directory[requested_user])
	message = 'Request: ' + requesting_user + ' wants your address. [allow ' + requesting_user + '] to accept.'
	send_message(sock, message)
	sock.close()

# assumes consent given, sends the address
def give_address(requesting_user, requested_user):
	hostport = user_directory[requested_user]
	if requesting_user in online_users:
		tell_user(requesting_user, 'ADR|' + requested_user + '|' + hostport[0] + '|' + str(hostport[1]))
	else:
		tell_user(requested_user, requesting_user + ' has gone offline. Please allow access when they are online again.')

# returns whether a user has been blocked by another user
def has_blocked(blocker, blockee):
	if blocker in block_directory:
		blocked_users = block_directory[blocker]
		if blockee in blocked_users:
			return True
		else:
			return False
	else:
		return False

# handles heartbeat messages from clients
def refresh(username):
	if username in online_users:
		online_users[username] = time.time()

# will occasionally update the online users
def heartbeat():
	to_delete = []
	while 1:
		time.sleep(5.0)
		now = time.time()
		for key in online_users:
			difference = now - online_users[key]
			if difference > 30.0:
				to_delete.append(key)
				tell_everyone(key, key + ' is offline.')
	for name in to_delete:
		del online_users[name]

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

# called only once, just reads credentials.txt
def load_credentials_file():
	f = open('credentials.txt', 'r')
	creds = dict()
	for line in f:
		t = line.partition(" ")
		creds[t[0]] = t[2].rstrip('\n')
	return creds

if __name__ == "__main__":
	try:
		heartbeat_thread = threading.Thread(target=heartbeat)
		heartbeat_thread.daemon = True
		heartbeat_thread.start()
		creds = load_credentials_file()
		sock = socket.socket()
		sock.bind((host, port))
		sock.listen(5)
		while 1:
			conn, client_addr = sock.accept()
			thread.start_new_thread(handler, (conn, client_addr))
	except KeyboardInterrupt:
		print 'goodbye!'
	sys.exit(1)