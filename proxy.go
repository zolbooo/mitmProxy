package mitmproxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

/*
 * TODO:
1) Call StartProxyServer
 * In ProxyEventHandler:
2) Change ClientRequest
3) Call SendRequest(), ServerResponse it set after calling this function
4) Call SendResponse()
*/

// StartProxyServer listens for all the connections to the proxy server and handles requests.
// Address is listen address, e.g.: ":8090", "0.0.0.0:8011"
func StartProxyServer(address string, proxyRequestHandler func(*ProxyRequest)) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err == nil {
			go handleConnection(conn, proxyRequestHandler)
		}
	}
}

func handleConnection(conn net.Conn, proxyRequestHandler func(*ProxyRequest)) {
	connReader := bufio.NewReader(conn)
	request, err := http.ReadRequest(connReader)
	if err != nil {
		return
	}

	proxyRequest := new(ProxyRequest)
	if request.Method == "CONNECT" {
		// We got HTTPS request, setup MITM connection and that pass request to the handler
		var sitecert *tls.Certificate
		if strings.Index(request.Host, ":") != -1 {
			sitecert, err = GenCert([]string{request.Host[:strings.Index(request.Host, ":")]})
		} else {
			sitecert, err = GenCert([]string{request.Host})
		}

		serverConn, err := tls.Dial("tcp", request.Host, nil)
		if err != nil {
			writeError(conn, http.StatusBadGateway)
			return
		}
		defer serverConn.Close()
		writeError(conn, http.StatusOK)
		clientConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{*sitecert},
		})
		defer clientConn.Close()

		proxyRequest.IsSSL = true
		proxyRequest.clientConn = clientConn
		proxyRequest.serverConn = serverConn

		proxyRequest.ClientRequest, err = http.ReadRequest(bufio.NewReader(clientConn))
		if err != nil {
			return
		}
	} else if request.URL.Path == "/" {
		defer conn.Close()

		resp := new(http.Response)
		resp.Status = "200 OK"
		resp.StatusCode = 200
		resp.Proto = request.Proto
		resp.ProtoMajor = request.ProtoMajor
		resp.ProtoMinor = request.ProtoMinor
		resp.Header = make(http.Header)
		resp.Header.Add("Content-Type", "text/plain")
		resp.Header.Add("Content-Disposition", "attachment; filename=\"rootCA.pem\"")

		file, err := os.OpenFile("./certificates/rootCA.pem", os.O_RDONLY, 0600)
		if err != nil {
			writeError(conn, http.StatusBadGateway)
			return
		}
		resp.Body = file

		if err = resp.Write(conn); err != nil {
			writeError(conn, http.StatusBadGateway)
		}
		return
	} else {
		// We got raw HTTP request, connect to the server and pass request to the handler
		serverConn, err := net.Dial("tcp", request.Host+":80")
		if err != nil {
			writeError(conn, http.StatusBadGateway)
			return
		}
		defer serverConn.Close()
		defer conn.Close()

		proxyRequest.clientConn = conn
		proxyRequest.serverConn = serverConn
		proxyRequest.ClientRequest = request
	}

	proxyRequestHandler(proxyRequest)
}

func writeError(conn net.Conn, errorCode int) error {
	_, err := conn.Write([]byte("HTTP/1.1 " + strconv.Itoa(errorCode) + " " + http.StatusText(errorCode) + "\r\n\r\n"))
	return err
}
