package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/websocket"

	"../Public"
)
type config struct {
	Listen string `json:"listen"`
	Key string `json:"key"`
	Users []client
}
type client struct {
	Name string `json:"name"`
	Color string `json:"color"`
	Key string `json:"password"`
}
type clientsS struct {
	con *websocket.Conn
	key []byte
}

var Config config
var clients = make(map[string]*clientsS)
var keys [][]byte
var upgrader = websocket.Upgrader{} // use default options
var aead cipher.AEAD

const VersionS = "0.0.0 / Build 1 / Server Application"

func main() {
	//Parse arguments
	{
		configFileName := flag.String("config", "config.json", "The config filename")
		help := flag.Bool("h", false, "Show help")
		keyGenerate := flag.Bool("k",false,"Generate server key")
		flag.Parse()

		if *help {
			fmt.Println("Created by Hirbod Behnam")
			fmt.Println("Source at https://github.com/HirbodBehnam/Chat-Go")
			fmt.Println("Version", VersionS)
			flag.PrintDefaults()
			os.Exit(0)
		}

		if *keyGenerate{
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				panic("Error creating the keys: "+ err.Error())
			}
			fmt.Println(hex.EncodeToString(b))
			os.Exit(0)
		}

		//Parse the server config
		//At first read the config file
		confF, err := ioutil.ReadFile(*configFileName)
		if err != nil {
			panic("Cannot read the config file. (io Error) " + err.Error())
		}
		err = json.Unmarshal(confF, &Config)
		if err != nil {
			panic("Cannot read the config file. (Parse Error) " + err.Error())
		}
		//Set the server key
		sKey, err := hex.DecodeString(Config.Key)
		if err != nil {
			panic("Cannot convert Server key to hex: " + err.Error())
		}
		aead, err = chacha20poly1305.NewX(sKey)
		if err != nil {
			panic("Failed to instantiate XChaCha20-Poly1305:" + err.Error()) //This must be fatal
		}
		//Set all keys
		keys = make([][]byte, len(Config.Users))
		for i := range Config.Users{
			keys[i] = Internal.Sha256(Config.Users[i].Key)
		}
	}
	http.HandleFunc("/", server)
	log.Fatal(http.ListenAndServe(Config.Listen, nil))
}


func server(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	log.Println("Hello from",r.RemoteAddr)

	var User client
	var indexOfUser int
	//Store the client for sending the
	defer c.Close()
	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		if User.Key == "" {
			//Loop all the users
			for i,v := range Config.Users{
				msg, err := aead.Open(nil, keys[i], message, nil)
				if err == nil {//Break the loop
					User = v
					message = msg
					indexOfUser = i
					break
				}
			}
			//Check if the user is found
			if User.Key == ""{
				log.Println("Invalid password or server key from:",r.RemoteAddr)
				return
			}
		}else{
			message, err = aead.Open(nil, keys[indexOfUser], message, nil)
			if err != nil { //How
				log.Println(err.Error())
				return
			}
		}
		//Parse the json
		var msg Internal.InputTemplate
		err = json.Unmarshal(message, &msg)
		if err != nil {
			log.Println("Error on parsing json:", err)
			continue //Serve the next message; (or maybe use break to close the connection?)
		}
		switch msg.Type {
		case 0: //Establish connection
			clients[User.Name] = &clientsS{
				con: c,
				key: keys[indexOfUser],
			} //Add the user to server
			j, _ := json.Marshal(Internal.MSGTemplate{MSG: User.Name + " has joined the chat", From: "SERVER", Color: "red"})
			for _, i := range clients {
				//Encrypt the data
				b := aead.Seal(nil, i.key, j, nil)
				//s := hex.EncodeToString()
				//Send the data
				err = i.con.WriteMessage(websocket.TextMessage,b)
				if err != nil {
					log.Println("write:", err)
					continue
				}
			}
		case 1: //Closing the connection
			delete(clients, User.Name)
			j, _ := json.Marshal(Internal.MSGTemplate{MSG: User.Name + " has left the chat", From: "SERVER", Color: "red"})
			for _, i := range clients {
				/*if i.con == *c{ //Do not send this to the user itself
					continue
				}*/
				//Encrypt the data
				b := aead.Seal(nil, i.key, j, nil)
				//s := hex.EncodeToString(b)
				//Send the data
				err = i.con.WriteMessage(websocket.BinaryMessage,b)
				if err != nil {
					log.Println("write:", err)
					continue
				}
			}
		case 2: //Send this to all active clients
			j, _ := json.Marshal(Internal.MSGTemplate{MSG: msg.MSG, From: User.Name, Color:  User.Color})
			for _,i := range clients {
				//Encrypt the data
				b := aead.Seal(nil, i.key, j, nil)
				//s := hex.EncodeToString(b)
				//Send the message
				err = i.con.WriteMessage(websocket.BinaryMessage, b)
				if err != nil {
					log.Println("write:", err)
					continue
				}
			}
		}

	}
}