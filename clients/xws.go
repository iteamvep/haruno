package clients

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/haruno-bot/haruno/logger"
	"github.com/haruno-bot/haruno/util"
	"github.com/haruno-bot/haruno/xproject"
)

// XWSClient 拓展的websocket客户端，可以自动重连
// 这个没有默认的客户端
type XWSClient struct {
	Name         string
	OnMessage    func([]byte)
	OnError      func(error)
	OnConnect    func(*XWSClient)
	Filter       func([]byte) bool
	SymmetricKey []byte
	conn         *websocket.Conn
	url          string
	token        string
	publickeyURL string
	authURL      string
	closed       bool
	rquit        chan int
	wquit        chan int
	dialer       *websocket.Dialer
	mmu          sync.Mutex
	cmu          sync.Mutex
}

// Dial 设置和远程服务器链接
func (c *XWSClient) Dial(token, url, publickeyURL, authURL string) error {
	c.closed = true
	c.token = token
	c.url = url
	c.publickeyURL = publickeyURL
	c.authURL = authURL
	if c.Name == "" {
		c.Name = "XControlled-Module Websocket"
	}
	if c.dialer == nil {
		c.dialer = &websocket.Dialer{
			Proxy: http.ProxyFromEnvironment,
		}
	}
	var err error
	c.SymmetricKey = util.GenKey(32)
	voucher, err := xproject.GetVoucher(c.SymmetricKey, token, publickeyURL, authURL)
	if err != nil {
		logger.Logger.Errorf(c.Name, "has broken down, will reconnect after 5s.", err)
		return err
	}
	c.conn, _, err = c.dialer.Dial(url, http.Header{
		"x-access-token": []string{voucher},
	})
	if err != nil {
		return err
	}
	c.closed = false
	c.rquit = make(chan int)
	c.wquit = make(chan int)
	if c.OnConnect != nil {
		go c.OnConnect(c)
	}
	go func() {
		for {
			var msg []byte
			if _, msg, err = c.conn.ReadMessage(); err != nil {
				if c.OnError != nil {
					go c.OnError(err)
				}
				close(c.rquit)
				return
			}
			if c.Filter != nil {
				if !c.Filter(msg) {
					continue
				}
			}
			if c.OnMessage != nil {
				go c.OnMessage(msg)
			}
		}
	}()
	go c.setupPing()
	return nil
}

// Send 发送消息
func (c *XWSClient) Send(msgType int, msg []byte) error {
	if c.closed {
		return errors.New("can not use closed connection")
	}
	c.mmu.Lock()
	defer c.mmu.Unlock()
	err := c.conn.WriteMessage(msgType, msg)
	if err != nil {
		close(c.wquit)
		if c.OnError != nil {
			go c.OnError(err)
		}
		return err
	}
	return nil
}

// IsConnected 检查是否在连接状态
func (c *XWSClient) IsConnected() bool {
	return !c.closed
}

func (c *XWSClient) close() {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if c.closed {
		return
	}
	if c.conn != nil {
		c.conn.Close()
	}
	c.closed = true
	for {
		if err := c.Dial(c.token, c.url, c.publickeyURL, c.authURL); err == nil {
			return
		}
		logger.Logger.Println(c.Name, "has broken down, will reconnect after 5s.")
		time.Sleep(time.Second * 5)
	}
}

func (c *XWSClient) setupPing() {
	pingTicker := time.NewTicker(time.Second * 5)
	pingMsg := []byte("")
	defer pingTicker.Stop()
	defer c.close()
	for {
		select {
		case <-c.rquit:
			return
		case <-c.wquit:
			return
		case <-pingTicker.C:
			if c.Send(websocket.PingMessage, pingMsg) != nil {
				return
			}
		}
	}
}
