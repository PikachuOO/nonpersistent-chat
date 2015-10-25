# non-persistent chatroom
For CSEE W4119 Computer Networks. 


## running this thing

Server (Message Center) takes two arguments, address and port.
Client takes four arguments: server's address/port, and client's own address/port.

```
python server.py localhost 6066
python client.py localhost 6066 localhost 6067
```

Since this is a p2p application, each client is also listening on its own socket to any incoming connections. If all clients are running on localhost, they should be listening on different ports. 

Subsequent clients:
```
python client.py localhost 6066 localhost 6068
python client.py localhost 6066 localhost 6069
```
etc.

## protocol overview

I implemented two layers of protocol for this project.

### MESSAGE SENDING
For any two entities (client-client, or client-server) to send data to each other, they follow this procedure.
ALICE: sends length of message
BOB: receives length of message
ALICE: sends her message
BOB: knowing the length, receives the full message.

The "length" value is packed into a struct of length 4 bytes.

### COMMANDS FROM CLIENT TO MESSAGE CENTER
When the user inputs any command, the client reads this input and interprets it as one of a number of actions. This request is then formatted
`REQUEST_TYPE|client_username|client_token|[any other data]`

The following are request types:
* LIN - log in
* MSG - message
* BRD - broadcast
* ONL - online
* BLC - block/unblock
* OUT - logout
* GET - getaddress
* HEY - keep alive

## general overview
The server binds to an address/port and is always listening for incoming connections. Once a connection is established, it creates a thread to parse and respond to any messages sent through that connection. Afterwards, it closes the socket.

The client also binds to an address/port and listens for incoming connections. It also sends a "LOG IN" message to the server, indicating that the client wants to log in. The user has no control over the sending of this message, and cannot do anything until the "log in" succeeds.

After logging in, the client's address/port is added to the server's list of known clients. An auth token is created and given to the client. From now on, whenever the client wishes to do an action, the auth token will be evaluated. When the same username is logged into from another location, the initial auth token will be revoked.

All functionality specified in the assignment has been implemented.

In addition, P2P privacy/consent and Guaranteed Message Delivery have been implemented. For P2P consent, when a requester seeks another user's info, a message will display on the requested user's console. This user can then type "allow <requester name>" to allow this. They can also ignore the message if they so choose.

## sample commands
TERMINAL 1
```
$ python server.py localhost 6066
```

TERMINAL 2
```
$ python client.py localhost 6066 localhost 6067
>Username: seas
>Password: summerisover
Welcome, seas !
```
_________________________________________________

TERMINAL 2
```
$ python client.py localhost 6066 localhost 6067
>Username: seas
>Password: asdf
Incorrect username/password. 2 more login attempts.
>Username: seas
>Password: asdf
Incorrect username/password. 1 more login attempts.
>Username: seas
>Password: asdf
Too many login attempts. Please wait 59.9988059998 seconds.
>Username: seas
>Password: summerisover
seas is suspended for another 19.9206991196 seconds.
>Username: seas
>Password: summerisover
Welcome, seas !
```

TERMINAL 3
```
$ python client.py localhost 6066 localhost 6068
>Username: google
>Password: hasglasses
Welcome, google !
```

TERMINAL 2
```
google has logged on.
```

TERMINAL 3
```
>logout
```

TERMINAL 2
```
google is offline.
```

TERMINAL 4
```
$ python client.py localhost 6066 localhost 6069
>Username: seas
>Password: summerisover
Welcome, seas !
```

TERMINAL 2
```
Logged on different location!
```
_______________________________________________

TERMINAL 1 (client, username: seas)
```
>getaddress google
Request has been sent.
```

TERMINAL 2 (client, username: google)
```
Request: seas wants your address. [allow seas] to accept.
>allow seas
```

TERMINAL 1
```
You can now privately message google
private google Hello.
```

TERMINAL 2
```
<seas>: Hello.
```