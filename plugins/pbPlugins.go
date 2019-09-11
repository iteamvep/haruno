package plugins

import (
	"github.com/haruno-bot/enshuhelper"
	"github.com/haruno-bot/haruno/coolq"
	"github.com/haruno-bot/retweetbot"
	"github.com/haruno-bot/senkamonitor"
)

// SetupPbPlugins 安装插件的入口
func SetupPbPlugins() {
	coolq.PbPluginRegister(retweetbot.Instance, enshuhelper.Instance, senkamonitor.Instance)
}
