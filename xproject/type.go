package xproject

type websocketSystem struct {
	MsgType string `json:"msg_type"`
	Data    string `json:"data"`
}

//WebResponseProto
type WebResponseProto struct {
	ResultType ResultType `json:"status"`
	Msg        string     `json:"msg"`
	Data       string     `json:"data"`
}

// ResultType msg result type
type ResultType string

// ResultType
const (
	SUCCESS ResultType = "SUCCESS"
	FAIL               = "FAIL"
	ERROR              = "ERROR"
)

// ProtoType msg type
type ProtoType string

// ProtoType
const (
	SYSTEM     ProtoType = "SYSTEM"
	NON_SYSTEM           = "NON_SYSTEM"
)
