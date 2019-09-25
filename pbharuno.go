package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/haruno-bot/haruno/coolq"
	"github.com/haruno-bot/haruno/logger"
	"github.com/haruno-bot/haruno/plugins"
	"github.com/haruno-bot/haruno/util"
	"golang.org/x/sys/windows"
)

type config struct {
	Version      string `toml:"version"`
	LogsPath     string `toml:"logsPath"`
	ServerPort   int    `toml:"serverPort"`
	CQWSURL      string `toml:"cqWSURL"`
	CQHTTPURL    string `toml:"cqHTTPURL"`
	CQToken      string `toml:"cqToken"`
	ServWSURL    string `toml:"servWSURL"`
	ServWSToken  string `toml:"servWSToken"`
	ServHTTPURL  string `toml:"servHTTPURL"`
	PublickeyURL string `toml:"publickeyURL"`
	AuthURL      string `toml:"authURL"`
	Notifier     string `toml:"notifier"`
	WebRoot      string `toml:"webroot"`
}

// haruno 晴乃机器人
// 机器人运行的全局属性
type haruno struct {
	startTime    int64
	port         int
	logpath      string
	version      string
	cqWSURL      string
	cqHTTPURL    string
	cqToken      string
	servWSURL    string
	servWSToken  string
	servHTTPURL  string
	publickeyURL string
	authURL      string
	notifier     string
	webRoot      string
	in           windows.Handle
	inMode       uint32
	out          windows.Handle
	outMode      uint32
	err          windows.Handle
	errMode      uint32
}

const waitTime = time.Second * 15

var bot = new(haruno)

func (bot *haruno) initStdios() {
	bot.in = windows.Handle(os.Stdin.Fd())
	if err := windows.GetConsoleMode(bot.in, &bot.inMode); err == nil {
		var mode uint32
		// Disable these modes
		mode &^= windows.ENABLE_QUICK_EDIT_MODE
		mode &^= windows.ENABLE_INSERT_MODE
		mode &^= windows.ENABLE_MOUSE_INPUT
		mode &^= windows.ENABLE_EXTENDED_FLAGS

		// Enable these modes
		mode |= windows.ENABLE_PROCESSED_INPUT
		mode |= windows.ENABLE_WINDOW_INPUT
		mode |= windows.ENABLE_AUTO_POSITION

		bot.inMode = mode
		windows.SetConsoleMode(bot.in, bot.inMode)
	} else {
		logger.Logger.Printf("failed to get console mode for stdin: %v\n", err)
	}

	bot.out = windows.Handle(os.Stdout.Fd())
	if err := windows.GetConsoleMode(bot.out, &bot.outMode); err == nil {
		if err := windows.SetConsoleMode(bot.out, bot.outMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err == nil {
			bot.outMode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		} else {
			windows.SetConsoleMode(bot.out, bot.outMode)
		}
	} else {
		logger.Logger.Printf("failed to get console mode for stdout: %v\n", err)
	}

	bot.err = windows.Handle(os.Stderr.Fd())
	if err := windows.GetConsoleMode(bot.err, &bot.errMode); err == nil {
		if err := windows.SetConsoleMode(bot.err, bot.errMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err == nil {
			bot.errMode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		} else {
			windows.SetConsoleMode(bot.err, bot.errMode)
		}
	} else {
		logger.Logger.Printf("failed to get console mode for stderr: %v\n", err)
	}
}

func (bot *haruno) loadConfig() {
	cfg := new(config)
	_, err := toml.DecodeFile("config.toml", cfg)
	if err != nil {
		logger.Logger.Fatalln("Haruno Initialize fialed", err)
	}
	bot.startTime = time.Now().UnixNano() / 1e6
	bot.port = cfg.ServerPort
	bot.logpath = cfg.LogsPath
	bot.version = cfg.Version
	bot.cqWSURL = cfg.CQWSURL
	bot.webRoot = cfg.WebRoot
	bot.cqHTTPURL = cfg.CQHTTPURL
	bot.cqToken = cfg.CQToken
	bot.servWSURL = cfg.ServWSURL
	bot.servWSToken = cfg.ServWSToken
	bot.servHTTPURL = cfg.ServHTTPURL
	bot.publickeyURL = cfg.PublickeyURL
	bot.authURL = cfg.AuthURL
	bot.notifier = cfg.Notifier
}

// Initialize 从配置文件读取配置初始化
func (bot *haruno) Initialize() {
	bot.initStdios()
	bot.loadConfig()
	// 设置环境变量
	os.Setenv("CQHTTPURL", bot.cqHTTPURL)
	os.Setenv("CQWSURL", bot.cqWSURL)
	os.Setenv("CQTOKEN", bot.cqToken)
	logger.Service.SetLogsPath(bot.logpath)
	logger.Service.Initialize()
	plugins.SetupPbPlugins()
	coolq.PbClient.Initialize(bot.cqToken, bot.notifier)
	go coolq.PbClient.Connect(bot.cqWSURL, bot.cqHTTPURL, bot.servWSURL, bot.servWSToken, bot.publickeyURL, bot.authURL)
	go coolq.PbClient.RegisterAllPlugins()
}

// Status 运行状态json格式
type Status struct {
	Go      int    `json:"go"`
	Version string `json:"version"`
	Success int    `json:"success"`
	Fails   int    `json:"fails"`
	Start   int64  `json:"start"`
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	status := new(Status)
	status.Fails = logger.Service.FailCnt()
	status.Success = logger.Service.SuccessCnt()
	status.Start = bot.startTime
	status.Version = bot.version
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	status.Go = runtime.NumGoroutine()
	json.NewEncoder(w).Encode(status)
}

// Run 启动机器人
func (bot *haruno) Run() {
	r := mux.NewRouter()

	if bot.webRoot != "" {
		_, err := os.Stat(bot.webRoot)
		if err == nil {
			logger.Logger.Println("the web page root found in", fmt.Sprintf("\"%s\"", bot.webRoot))
			page := http.FileServer(http.Dir(bot.webRoot))
			r.Methods(http.MethodGet).Path("/").Handler(page)
			r.Methods(http.MethodGet).PathPrefix("/static").Handler(page)
		}
	}

	r.Methods(http.MethodGet).Path("/status").HandlerFunc(statusHandler)
	r.Methods(http.MethodGet).Path("/logs/-/type=websocket").HandlerFunc(logger.WSLogHandler)
	r.Methods(http.MethodGet).Path("/logs/-/type=plain").HandlerFunc(logger.RawLogHandler)

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", bot.port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	go func() {
		logger.Logger.Printf("haruno is listening on http://localhost:%d", bot.port)

		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			logger.Logger.Fatalln(err)
		}
	}()

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt, os.Kill)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), waitTime)
	defer cancel()

	srv.Shutdown(ctx)

	logger.Logger.Println("haruno is shutting down")

	os.Exit(0)
}

func main() {
	defer func() { //catch or finally
		if err := recover(); err != nil { //catch
			fmt.Printf("main - Exception: %v\n", err)
			os.Exit(1)
		}
	}()
	// rsatest()
	// aestest()

	bot.Initialize()
	bot.Run()
}

// var privkey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCH64Fuga9Smdg1zF3rKGfjgJZvgjRV714WPEFrbdc72KC6Z/YHxVS1krVgIDtc+SKGwLSi2AqUwTBJtEprdEFc6k6YjTBkSxTU/0WBTYNghbslP5KiAeeGmg+WIUUGAyAaZKE/fisSrkwizozujW8P0QoaABJyd7jkjb5+4SOuAmszvtl84PFkkNhbMrxGQMSiQ/lMjMo7g8QFPRxCx7YfiiJidMiSWzuZhVi/QDs8TuLiBIa5IiJT0K1TPl741lCmzgMJloTPrjQRJl4tgaxV4TNAtZMOIAqHW9zTyDQuhfWWgRRKjt20bHLRcPP0enKmyuEWOaKVUF8FXMpU4k0TAgMBAAECggEAVsJcPxamu9oZ6dVGyfljvxNwc0Mwdv4xF45kz9cwQTI4/mOn5zPtq203O2G3otQgVtWhOCUhM+zRDur3afmuU0n422WcUxid9ovvaOb6il0ypUccKS+AAypJ8rHP5lOOZWqAhw/ZHLaHQNyJlyhOkVEE2q3bGJgVPEbCJyk85jAQ7r1cvYvwxFAtKQLnW0pJnGFj/6rGVt/r/Ptv/6eRWRR9bFhfzwwr2432dnCgcjOg6gzvawGSrz1y+ejjatOdNyY/AwPRmU6BO+JoeqTIPvDuIl/2vdlw0YWsteginrdf8PEobw6nmFBWFnFwzNXomWd+C/Bn2gcWIfeT83oUeQKBgQDf86AFiPGka/04/jz5Vs5VmwyKKwlLdw0a00bze70GE/ylSDProCc1OVNI0/RFAr8Pl8PCvgoEENJgANaEwVmTWli69/lODsMMl0Z2s8BElkr9SigHVeVRibBdwa62WvBWN4Orj/CQmuqSUt1G/kxSfYIZRjVpjWsxF0BPibZwJwKBgQCbXuAl+utNe8ZD4vpsHaVUrenkBT4ciDiKwDoLNpqrPlDF+bRhmoQZngwSYHFwUtXO3IeusPMVnzubSHTBr2TZL97sNNIv74S6RqyjadY+OpIZFT3xErfmhU6i9uxq6v3qE6tqsrrNWQEhhbimCelVN029oIBaek6eXuvSzhJjNQKBgHCtlV/zjREbPGcGlAsn/9zWjDKggKa1maRblSFAqtR6De3jLCxrgg6nbx3/drGaNiNUSqybDVMKW67t/QECf11CYc6AobECgGS/YDatLhnUPJrASu+V6jFiQ5iIsK0TiET43YjefT1klI1Wn/ruS9xdRa4NwyX+f2ZNuo/KTD6VAoGAbecAuxzw0RBawK6P4WZfCrUymx6yPtCE3nD3HfN0GOmtjT0CwX/hLZXEiEM8Ou39W6RXPdThPkwyh7cLD+6XcaIRGBiNDWdqBbH0cGtvJvmbWq7R7/MDrsZhR5lOxpqPHcLoIENpK9RnnmTOpnSgXq0OCrK72ERn1FLkkWs/SnkCgYEAr26oogQtUqrDB40snX7qqu88ykKxEPZaRISWVDTPyc+ETLiZMUf4bVy6+MHRfNsKZgKH7D+ghABje2fNVOXk1rSiLMvZjpbnX5g+FNitFZZBBcD0ibJ8s9FhLTstxEWBwYQykjEgV33bj0kpzW+jOFJahBlfIOeslYcrW6OzPqY="
// var pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh+uBboGvUpnYNcxd6yhn44CWb4I0Ve9eFjxBa23XO9igumf2B8VUtZK1YCA7XPkihsC0otgKlMEwSbRKa3RBXOpOmI0wZEsU1P9FgU2DYIW7JT+SogHnhpoPliFFBgMgGmShP34rEq5MIs6M7o1vD9EKGgAScne45I2+fuEjrgJrM77ZfODxZJDYWzK8RkDEokP5TIzKO4PEBT0cQse2H4oiYnTIkls7mYVYv0A7PE7i4gSGuSIiU9CtUz5e+NZQps4DCZaEz640ESZeLYGsVeEzQLWTDiAKh1vc08g0LoX1loEUSo7dtGxy0XDz9HpypsrhFjmilVBfBVzKVOJNEwIDAQAB"

// var es = "by+vLMKsg+D6MAoIi1BAKFLOcGkg1PGmOJKpZ/a8QbtbrUkXn5Yj/hMiMS2qaXtCZp2prflNLkma7dpLMedVN/HzqD8JwuZKieATl/8B/CALSRFGXHyqNYjBvqVCrRI7n1WByxFhowEdSTkEd6OFmOgJKfXtj4RFrNfiz+RnRTS8Db9Fh97idJcuzupL8HmTlxD32Ql8WxqvQtZi6c928x2vd6t+XevHCYezHZQjNVQYixVkWIQSL2RbNDVfD3Kf1mqo0G05hPy9fDTpw2wkeVAUE5OeMx+8/kT6HwugMz71ZpzKhtzfhw3u5khR88mbFIkw3zb+hY+wCOvW2tTY4Q=="

var symmetricKey = "xDQxWW9rB/zVsYnUaz9/KodR9Akgq3bqm+3vCfXnEsk="
var es = "1532NiPZ4+L/WJKlx5DznWT8jhXoI3zf+COlKp+vBMKA71Zh7Q=="

func aestest() {
	key, err := base64.StdEncoding.DecodeString(symmetricKey)
	if err != nil {
		fmt.Println("failed to decode key: ", err)
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(es)
	if err != nil {
		fmt.Println("failed to decode cipherText: ", err)
	}
	plainBytes, err := util.AESGCMDecrypt(cipherBytes, key)
	if err != nil {
		fmt.Println("failed to decrypt cipherBytes:", err)
	}
	fmt.Println("rawdata:", string(plainBytes))
	plainText := "test123456"
	cipherBytes, err = util.AESGCMEncrypt([]byte(plainText), key)
	if err != nil {
		fmt.Println("failed to encrypt cipherBytes:", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key))
	fmt.Println(base64.StdEncoding.EncodeToString(cipherBytes))
}

// func rsatest() {
// 	// priv, pub := GenerateKeyPair(2048)
// 	// fmt.Println(base64.StdEncoding.EncodeToString(PrivateKeyToBytes(priv)))
// 	// fmt.Println(base64.StdEncoding.EncodeToString(PublicKeyToBytes(pub)))

// 	// privateKey, err := util.ReadPKCS8PrivateKey("private.pem")
// 	// publicKey := &privateKey.PublicKey
// 	// publicKey, err := util.ReadPKIXPublicKey("public.pem")

// 	// decpriv, err := base64.StdEncoding.DecodeString(privkey)
// 	// if err != nil {
// 	// 	logger.Logger.Fatalf("failed to decode public key: %s", err)
// 	// 	return
// 	// }
// 	// decpub, err := base64.StdEncoding.DecodeString(pubkey)
// 	// if err != nil {
// 	// 	logger.Logger.Fatalf("failed to decode public key: %s", err)
// 	// 	return
// 	// }
// 	privateKey, err := util.ParseBase64RAWPKCS8PrivateKey(privkey)
// 	publicKey, err := util.ParseBase64RAWPKIXPublicKey(pubkey)
// 	// ds, err := base64.StdEncoding.DecodeString(es)
// 	// if err != nil {
// 	// 	logger.Logger.Fatalf("failed to decode public key: %s", err)
// 	// 	return
// 	// }

// 	var plain = "VX is the author"

// 	ciphertext, err := util.PublicEncrypt([]byte(plain), publicKey)
// 	if err != nil {
// 		logger.Logger.Fatalf("failed to decode public key: %s", err)
// 		return
// 	}
// 	enc := base64.StdEncoding.EncodeToString(ciphertext)
// 	fmt.Println(enc)
// 	dec, err := base64.StdEncoding.DecodeString(enc)
// 	if err != nil {
// 		logger.Logger.Fatalf("failed to decode public key: %s", err)
// 		return
// 	}
// 	_, err = util.PublicDecrypt(dec, publicKey)
// 	if err != nil {
// 		logger.Logger.Print("failed to decode public key: %s", err)
// 	}
// 	orgi, err := util.PrivateDencrypt(dec, privateKey)
// 	if err != nil {
// 		logger.Logger.Fatalf("failed to decode public key: %s", err)
// 		return
// 	}
// 	fmt.Println(string(orgi))

// 	ciphertext, err = util.PrivateEncrypt([]byte(plain), privateKey)
// 	if err != nil {
// 		logger.Logger.Fatalf("failed to decode public key: %s", err)
// 		return
// 	}
// 	enc = base64.StdEncoding.EncodeToString(ciphertext)
// 	fmt.Println(enc)
// 	dec, err = base64.StdEncoding.DecodeString(enc)
// 	if err != nil {
// 		logger.Logger.Fatalf("failed to decode public key: %s", err)
// 		return
// 	}
// 	_, err = util.PrivateDencrypt(dec, privateKey)
// 	if err != nil {
// 		logger.Logger.Print("failed to decode public key: %s", err)
// 	}
// 	orgi, err = util.PublicDecrypt(dec, publicKey)
// 	if err != nil {
// 		logger.Logger.Fatalf("failed to decode public key: %s", err)
// 		return
// 	}
// 	fmt.Println(string(orgi))

// }
