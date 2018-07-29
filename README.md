# mitmProxy
SSL-capable man-in-the-middle proxy written on Golang

First, you should create folder for certificates (/app/certificates)
Then you should call StartProxyServer func in order to listen for all requests.

## Documentation
### StartProxyServer
Type: function
Signature:
```
func StartProxyServer(address string, proxyRequestHandler func(*ProxyRequest)) error
```
* Address is listen address, e.g.: ":8090", "0.0.0.0:8011"
* proxyRequestHandler is handler for all incoming connections, ProxyRequest structure is passed
### ProxyRequest
Type: struct

Signature:
```
type ProxyRequest struct {
	IsSSL          bool
	ClientRequest  *http.Request
	ServerResponse *http.Response

	clientConn, serverConn io.ReadWriter
}
func (pr *ProxyRequest) SendRequest() error
func (pr *ProxyRequest) SendResponse() error
```
Fields:
* IsSSL is set when incoming connection is http CONNECT request
* ClientRequest is request sent by proxy client
* SendRequest establishes connection to the remote server and sends client's request
* ServerResponse is remote server's response
* SendResponse sends ProxyRequest.ServerResponse to the client.

## Example
``` 
package main

import (
	"fmt"

	"mitmProxy"
)

func main() {
	mitmproxy.StartProxyServer(":4444", func(req *mitmproxy.ProxyRequest) {
		fmt.Println(req.ClientRequest)
		req.SendRequest()
		fmt.Println(req.ServerResponse)
		req.SendResponse()
	})
}
```
