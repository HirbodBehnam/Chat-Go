package Internal

type InputTemplate struct {
	// 0: Establish Connection
	// 1: Close connection
	// 2: Message
	Type byte   `json:"type"`
	MSG  string `json:"msg"` // The message (can be empty)
}
type MSGTemplate struct {
	MSG   string `json:"msg"`
	From  string `json:"from"`
	Color string `json:"color"`
}
