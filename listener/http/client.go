package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/eyslce/routune/adapter/inbound"
	C "github.com/eyslce/routune/constant"
	"github.com/eyslce/routune/transport/socks5"
)

func newClient(source net.Addr, originTarget net.Addr, in chan<- C.ConnContext) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// from http.DefaultTransport
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext: func(context context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" && network != "tcp6" {
					return nil, errors.New("unsupported network " + network)
				}

				dstAddr := socks5.ParseAddr(address)
				if dstAddr == nil {
					return nil, socks5.ErrAddressNotSupported
				}

				left, right := net.Pipe()

				in <- inbound.NewHTTP(dstAddr, source, originTarget, right)

				return left, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
