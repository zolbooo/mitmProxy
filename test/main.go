package main

import (
	"io"

	mitmproxy ".."
)

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error {
	return nil
}

func intercept(req *mitmproxy.ProxyRequest) {
	if err := req.SendRequest(); err == nil {
		req.SendResponse()
	}
}

func main() {
	panic(mitmproxy.StartProxyServer(":8080", intercept))
}
