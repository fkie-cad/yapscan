package output

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/targodan/go-errors"
)

type OutputProxyServer struct {
	outListener net.Listener
	errListener net.Listener

	outConn net.Conn
	errConn net.Conn
}

func NewOutputProxyServer() *OutputProxyServer {
	return &OutputProxyServer{}
}

func (p *OutputProxyServer) Listen() error {
	lOut, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}
	lErr, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		lOut.Close()
		return err
	}

	p.outListener = lOut
	p.errListener = lErr

	return nil
}

func (p *OutputProxyServer) addrToPort(addr string) int {
	parts := strings.Split(addr, ":")
	portStr := parts[len(parts)-1]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		panic(err)
	}
	return int(port)
}

func (p *OutputProxyServer) StdoutPort() int {
	return p.addrToPort(p.outListener.Addr().String())
}

func (p *OutputProxyServer) StderrPort() int {
	return p.addrToPort(p.errListener.Addr().String())
}

func (p *OutputProxyServer) acceptWatchdog(ctx context.Context) {
	<-ctx.Done()

	if p.outConn == nil || p.errConn == nil {
		p.Close()
	}
}

func (p *OutputProxyServer) WaitForConnection(ctx context.Context) error {
	acceptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go p.acceptWatchdog(acceptCtx)

	errChan := make(chan error)

	go func() {
		var err error
		p.outConn, err = p.outListener.Accept()
		errChan <- err
	}()

	go func() {
		var err error
		p.errConn, err = p.errListener.Accept()
		errChan <- err
	}()

	var err error
	err = errors.NewMultiError(err, <-errChan)
	err = errors.NewMultiError(err, <-errChan)
	return err
}

func (p *OutputProxyServer) ReceiveAndOutput(ctx context.Context, stdout io.Writer, stderr io.Writer) error {
	acceptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go p.acceptWatchdog(acceptCtx)

	errChan := make(chan error)

	go func() {
		_, err := io.Copy(stdout, p.outConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(stderr, p.errConn)
		errChan <- err
	}()

	var err error
	err = errors.NewMultiError(err, <-errChan)
	err = errors.NewMultiError(err, <-errChan)
	return err
}

func (p *OutputProxyServer) Close() (err error) {
	if p.outConn != nil {
		err = errors.NewMultiError(err, p.outConn.Close())
	}
	if p.errConn != nil {
		err = errors.NewMultiError(err, p.errConn.Close())
	}

	err = errors.NewMultiError(err, p.outListener.Close())
	err = errors.NewMultiError(err, p.errListener.Close())

	return err
}

type timeoutConn struct {
	conn net.Conn
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	c.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	return c.conn.Write(b)
}

type OutputProxyClient struct {
	outConn net.Conn
	errConn net.Conn

	Stdout *os.File
	Stderr *os.File
}

func NewOutputProxyClient() *OutputProxyClient {
	return &OutputProxyClient{}
}

func (p *OutputProxyClient) Connect(stdoutPort int, stderrPort int) (err error) {
	p.outConn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", stdoutPort))
	if err != nil {
		return
	}
	p.errConn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", stderrPort))
	if err != nil {
		return
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		p.Close()
		return err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		p.Close()
		return err
	}

	go func() {
		dst := &timeoutConn{conn: p.outConn}
		io.Copy(dst, outR)
	}()
	go func() {
		dst := &timeoutConn{conn: p.errConn}
		io.Copy(dst, errR)
	}()

	p.Stdout = outW
	p.Stderr = errW

	return
}

func (p *OutputProxyClient) Close() (err error) {
	if p.outConn != nil {
		err = errors.NewMultiError(err, p.outConn.Close())
	}
	if p.errConn != nil {
		err = errors.NewMultiError(err, p.errConn.Close())
	}
	return
}
