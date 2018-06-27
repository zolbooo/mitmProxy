package mitmproxy

import (
	"bufio"
	"io"
	"net/http"
)

// ProxyRequest is request sent by client to the proxy server
// ProxyRequest provides functions for mitm attack, e.g. modifying client requests and changing server responses
type ProxyRequest struct {
	IsSSL          bool
	ClientRequest  *http.Request
	ServerResponse *http.Response

	clientConn, serverConn io.ReadWriter
}

// SendRequest sends request to the server and reads corresponding response
func (pr *ProxyRequest) SendRequest() error {
	err := pr.ClientRequest.Write(pr.serverConn)
	if err != nil {
		return err
	}

	pr.ServerResponse, err = http.ReadResponse(bufio.NewReader(pr.serverConn), pr.ClientRequest)
	if err != nil {
		return err
	}
	return nil
}

// SendResponse sends modified response to the client
func (pr *ProxyRequest) SendResponse() error {
	return pr.ServerResponse.Write(pr.clientConn)
}
