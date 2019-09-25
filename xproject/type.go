package xproject

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

type WebsocketSystemProto struct {
	MsgType WebsocketSystemMessageType `json:"msg_type"`
	Data    string                     `json:"data"`
}

// WebsocketSystemMessageType msg type
type WebsocketSystemMessageType string

// WebsocketSystemMessageType
const (
	SystemInfo            WebsocketSystemMessageType = "SYSTEM_INFO"
	DebugMsg                                         = "DEBUG_MSG"
	PayloadError                                     = "PAYLOAD_ERROR"
	ClientReboot                                     = "CLIENT_REBOOT"
	ClientShutdown                                   = "CLIENT_SHUTDOWN"
	ServerReboot                                     = "SERVER_REBOOT"
	ServerShutdown                                   = "SERVER_SHUTDOWN"
	AuthorizationRequired                            = "AUTHORIZATION_REQUIRED"
	AuthorizationFail                                = "AUTHORIZATION_FAIL"
	AuthorizationSuccess                             = "AUTHORIZATION_SUCCESS"
	AccessDenied                                     = "ACCESS_DENIED"
	PermissionDenied                                 = "PERMISSION_DENIED"
	ModuleStatusNotify                               = "MODULE_STATUS_NOTIFY"
	Ping                                             = "PING"
)

type ModuleNotificationProto struct {
	Identity string `json:"identity"`
	ClientID string `json:"clientID"`
	Status   string `json:"status"`
	Msg      string `json:"msg"`
}
