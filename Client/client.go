package main

import (
	"../Public"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/marcusolsson/tui-go"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"time"
)

type config struct {
	Server     string `json:"server"`
	ServerKey  string `json:"server_key"`
	PrivateKey string `json:"private_key"`
}

var Config config
var Pass []byte
var aead cipher.AEAD

const VersionC = "0.0.0 / Build 1 / Client Application"

func main() {
	//Parse arguments
	{
		configFileName := flag.String("config", "config.json", "The config filename")
		help := flag.Bool("h", false, "Show help")
		flag.Parse()

		if *help {
			fmt.Println("Created by Hirbod Behnam")
			fmt.Println("Source at https://github.com/HirbodBehnam/Chat-Go")
			fmt.Println("Version", VersionC)
			flag.PrintDefaults()
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
		sKey, err := hex.DecodeString(Config.ServerKey)
		if err != nil {
			panic("Cannot convert Server key to hex: " + err.Error())
		}
		aead, err = chacha20poly1305.NewX(sKey)
		if err != nil {
			panic("Failed to instantiate XChaCha20-Poly1305:" + err.Error()) //This must be fatal
		}
		//Get the user key
		Pass, err = hex.DecodeString(Config.PrivateKey)
		if err != nil {
			panic("Cannot convert private key to hex: " + err.Error())
		}
	}
	//Connect to the server
	u := url.URL{Scheme: "ws", Host: Config.Server, Path: "/"}

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	//Run the tui
	t := tui.NewTheme()
	//Set themes
	t.SetStyle("label.black", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorBlack})
	t.SetStyle("label.white", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorWhite})
	t.SetStyle("label.red", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorRed})
	t.SetStyle("label.green", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorGreen})
	t.SetStyle("label.blue", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorBlue})
	t.SetStyle("label.cyan", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorCyan})
	t.SetStyle("label.magenta", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorMagenta})
	t.SetStyle("label.yellow", tui.Style{Bg: tui.ColorDefault, Fg: tui.ColorYellow})

	history := tui.NewVBox()

	historyScroll := tui.NewScrollArea(history)
	historyScroll.SetAutoscrollToBottom(true)

	historyBox := tui.NewVBox(historyScroll)
	historyBox.SetBorder(true)

	input := tui.NewEntry()
	input.SetFocused(true)
	input.SetSizePolicy(tui.Expanding, tui.Maximum)

	inputBox := tui.NewHBox(input)
	inputBox.SetBorder(true)
	inputBox.SetSizePolicy(tui.Expanding, tui.Maximum)

	chat := tui.NewVBox(historyBox, inputBox)
	chat.SetSizePolicy(tui.Expanding, tui.Expanding)

	input.OnSubmit(func(e *tui.Entry) {
		go func(m string) {
			b, _ := json.Marshal(Internal.InputTemplate{Type: 2, MSG: m})
			b = aead.Seal(nil, Pass, b, nil)
			err := c.WriteMessage(websocket.BinaryMessage, b)
			if err != nil {
				printOneLineMessage(history, "Cannot send message: "+err.Error(), "CLIENT", "red")
			}
		}(e.Text())
		input.SetText("")
	})

	ui, err := tui.New(chat)
	if err != nil {
		log.Fatal(err)
	}

	ui.SetTheme(t)
	ui.SetKeybinding("Esc", func() { ui.Quit() })
	ui.SetKeybinding("Up", func() { historyScroll.Scroll(0, -1) })
	ui.SetKeybinding("Down", func() { historyScroll.Scroll(0, 1) })

	//Before running just setup the connection
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Fatal("Error on reading message: " + err.Error())
			}
			message, err = aead.Open(nil, Pass, message, nil)
			if err != nil { //Break the loop
				printOneLineMessage(history, "Error decrypting message: "+err.Error(), "CLIENT", "red")
				ui.Update(func() {})
				continue //Or maybe break?
			}
			//Parse the data
			var msg Internal.MSGTemplate
			err = json.Unmarshal(message, &msg)
			if err == nil { //Ignore all the other data
				if msg.From != "SERVER" {
					printMessage(history, msg.MSG, msg.From, msg.Color)
					ui.Update(func() {})
				} else {
					printOneLineMessage(history, msg.MSG, "SERVER", msg.Color)
					ui.Update(func() {})
				}
			}
		}
	}()
	//Send the hello message
	go func() {
		b, _ := json.Marshal(Internal.InputTemplate{
			Type: 0,
			MSG:  "",
		})
		//Encrypt Message
		b = aead.Seal(nil, Pass, b, nil)
		//Send the message
		err := c.WriteMessage(websocket.BinaryMessage, b)
		if err != nil {
			log.Fatal("Error on sending hello:", err.Error())
		} else {
			printOneLineMessage(history, "Connected to "+c.RemoteAddr().String(), "CLIENT", "blue")
			ui.Update(func() {})
		}
	}()

	//Run the TUI
	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}
	//Inform the server because of close
	{
		//Encrypt the data
		b, _ := json.Marshal(Internal.InputTemplate{
			Type: 1,
			MSG:  "",
		})
		b = aead.Seal(nil, Pass, b, nil)
		//Send the message
		err := c.WriteMessage(websocket.BinaryMessage, b)
		if err != nil {
			log.Println("Error on sending by :", err.Error())
		}
	}
	//Close the websocket
	err = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println("write close:", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

func printOneLineMessage(history *tui.Box, Message, From, Color string) {
	lbl := tui.NewLabel(fmt.Sprintf("<%s>", From))
	lbl.SetStyleName(Color)
	history.Append(tui.NewHBox(
		tui.NewLabel(time.Now().Format("15:04:05")),
		tui.NewPadder(1, 0, lbl),
		tui.NewLabel(Message),
		tui.NewSpacer(),
	))
}

//Prints a message to tui
func printMessage(history *tui.Box, Message, From, Color string) {
	//Get the width to wrap the text if needed
	fd := int(os.Stdout.Fd())
	width, _, err := terminal.GetSize(fd)
	if err != nil { //Just a fallback
		width = 80
	}
	width -= 4 //Two for sides, and two for >
	//Print the user
	lbl := tui.NewLabel(fmt.Sprintf("<%s>", From))
	lbl.SetStyleName(Color)
	history.Append(tui.NewHBox(
		tui.NewLabel(time.Now().Format("15:04:05")),
		tui.NewPadder(1, 0, lbl),
		tui.NewSpacer(),
	))
	lbl = tui.NewLabel("> ")
	lbl.SetStyleName(Color)
	if len(Message) <= width {
		history.Append(tui.NewHBox(
			lbl,
			tui.NewLabel(Message),
			tui.NewSpacer(),
		))
	} else {
		x := Message[0:width]
		history.Append(tui.NewHBox(
			lbl,
			tui.NewLabel(x),
			tui.NewSpacer(),
		))
		i := 1
		for ; i < len(Message)/width; i++ {
			x = Message[i*width : (i+1)*width]
			history.Append(tui.NewHBox(
				lbl,
				tui.NewLabel(x),
				tui.NewSpacer(),
			))
		}
		x = Message[i*width:]
		history.Append(tui.NewHBox(
			lbl,
			tui.NewLabel(x),
			tui.NewSpacer(),
		))
	}
}
