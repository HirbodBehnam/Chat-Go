# GO Chat
A bullshit client and server for chat room.
## Features
* Encrypted: All chats are encrypted by xchacha-poly1305
* No Trace: Non of the chats will ever be saved. Everyone who is online will get the message; Others will not.
* TUI Interface: No need for GUI; Runs inside the terminal
## Install
### Server
Download the executable for your server from [releases](https://github.com/HirbodBehnam/Chat-Go/releases). Also download the config.json for server from [here](https://github.com/HirbodBehnam/Chat-Go/blob/master/Server/config.json)

Create a public key (it is not a _real_ public key but I call it public key) by running `./server -k`. Use the given value at `config.json` and the `key` value.

Edit the listen address as well.

For creating users you should at first create a private key. To do this, run `./server -p`. Then edit the config.json and add a user object to `users` array as follows:

* `name`: Just a name for the user.
* `color`: The color for the user. Acceptable values are `black`, `white`, `red`, `green`, `blue`, `cyan`, `magenta` and `yellow`.
* `key`: The key for the user that you just created.
#### Building from Source
```bash
git clone https://github.com/HirbodBehnam/Chat-Go
cd Chat-Go/Server
go get golang.org/x/crypto/chacha20poly1305
go get github.com/gorilla/websocket
go build server.go
```
### Client
Just send the user's private key, server's public key and server's address to client and tell them to enter the values into [config.json](https://github.com/HirbodBehnam/Chat-Go/blob/master/Client/config.json).

Run the client and they should connect to server.
#### Build
```bash
git clone https://github.com/HirbodBehnam/Chat-Go
cd Chat-Go/Client
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/crypto/ssh/terminal
go get github.com/gorilla/websocket
go get github.com/marcusolsson/tui-go
go build client.go
```
## Cryptography
The encryption in this chat application is so stupid! So for encrypting xchacha-poly1305 you need a main key and a nonce. The main key is the server public key and the nonce is the private key of the users. When a hello packet arrives, server tries to bruteforce the encryption! (AND THIS IS BEYOND STUPID) If a key decrypts the message, server will assign they key to that IP. So every other incoming message is also decrypted with that key.

Server lists all currently active users in a map.<sup>[s](https://github.com/HirbodBehnam/Chat-Go/blob/master/Server/server.go#L38)</sup> As you can see, two parameters are saved: 1. The Websocket connection 2. The private key. Each time server wants to send a message to clients, it loops through this map. At first it encrypts the message with their key, then it will send it through the `con` variable that is the websocket connection to them.

Closing connections are either _peaceful_ closing or not. Peaceful closes happen when the client closes peacefully (like exiting with escape button) so the client can send a goodbye message to server. In this case, at first the server will delete the connection from the `clients` map. Then it will send a message like `The user has left the chat` to all other clients. In the case that user goodbye is not peaceful, the websocket will throw an error on [ReadMessage](https://github.com/HirbodBehnam/Chat-Go/blob/master/Server/server.go#L133). Also in this case the server will delete the connection from the `clients` map and then sends an message to all other clients.