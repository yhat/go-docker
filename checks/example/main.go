package main

import (
	"os"

	"github.com/yhat/go-docker/checks"
)

func main() {
	c := checks.Checker{}
	c.Register(checks.CheckDockerSocket, "CheckDockerSocketAccess")
	c.Register(checks.CheckVersion([]int{1, 5, 0}), "CheckVersion")
	c.Register(checks.CheckDriver("aufs"), "CheckAUFSDriver")
	c.Register(checks.CheckSimpleCommand, "CheckSimpleCommand")
	c.Register(checks.CheckInternetAccess, "CheckInternetAccess")
	c.Register(checks.CheckExposedPort, "CheckExposingPort")
	c.Register(checks.CheckFileMounting, "CheckFileMounting")
	os.Exit(c.Run())
}
