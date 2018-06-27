package main

import (
	"fmt"
	"io"

	mitmproxy ".."
)

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error {
	return nil
}

func main() {
	panic(mitmproxy.StartProxyServer(":8080", func(req *mitmproxy.ProxyRequest) {
		if err := req.SendRequest(); err == nil {
			req.SendResponse()
		} else {
			fmt.Println(err)
		}
	}))
}
