package traceroute

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/models"
)

type Tracer struct {
	options Options
}

func NewTracer(cfg *config.ManagerConfig) *Tracer {
	t := new(Tracer)
	t.SetOptions(cfg)
	return t
}

type Hop struct {
	Id          int
	Destination string
	Success     bool
	Address     [4]byte
	Host        string
	ElapsedTime time.Duration
	TTL         int
}

func (hop *Hop) AddressString() string {
	return fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
}

type Options struct {
	port       int
	maxHops    int
	timeout    int
	retries    int
	packetSize int
}

func (t *Tracer) getListenAddr() ([4]byte, error) {
	ips, err := net.InterfaceAddrs()
	if err != nil {
		return [4]byte{}, err
	}

	var addr [4]byte
	for _, a := range ips {
		if IPNet, ok := a.(*net.IPNet); ok && !IPNet.IP.IsLoopback() {
			// Если у нас адрес IPv6, то метод To4 вернет nil
			if IPNet.IP.To4() != nil {
				copy(addr[:], IPNet.IP.To4())
				return addr, nil
			}
		}
	}

	err = errors.New("no ipv4 addresses found on interfaces other than loopback")

	return addr, err
}

func (t *Tracer) parseDestAddress(dest string) ([4]byte, error) {
	ips, err := net.LookupHost(dest)
	if err != nil {
		return [4]byte{}, err
	}

	ip, err := net.ResolveIPAddr("ip", ips[0])
	if err != nil {
		return [4]byte{}, err
	}
	destAddr := [4]byte{}

	copy(destAddr[:], ip.IP.To4())
	return destAddr, nil
}

func (t *Tracer) SetOptions(cfg *config.ManagerConfig) {
	t.options = Options{
		port:       cfg.Trace.Port,
		maxHops:    cfg.Trace.Max_hops,
		timeout:    cfg.Trace.Timeout_ms,
		retries:    cfg.Trace.Retries,
		packetSize: cfg.Trace.Packet_size,
	}
}

func (t *Tracer) Traceroute(id int, dest string, c chan Hop, result chan models.TraceResult) error {
	destAddr, err := t.parseDestAddress(dest)
	if err != nil {
		return err
	}

	socketAddr, err := t.getListenAddr()
	if err != nil {
		return err
	}

	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return err
	}

	recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer syscall.Close(recvSocket)
	defer syscall.Close(sendSocket)

	timeoutMs := (int64)(t.options.timeout)
	tv := syscall.NsecToTimeval(1000 * 1000 * timeoutMs)
	ttl := 1
	retry := 0

	for {
		start := time.Now()

		syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
		syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: t.options.port, Addr: socketAddr})
		syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: t.options.port, Addr: destAddr})

		var p = make([]byte, t.options.packetSize)
		_, from, err := syscall.Recvfrom(recvSocket, p, 0)
		elapsed := time.Since(start)

		if err != nil {
			retry += 1

			if retry > t.options.retries {
				c <- Hop{
					Id:          id,
					Destination: dest,
					Success:     false,
					Address:     [4]byte{},
					Host:        "",
					ElapsedTime: elapsed,
					TTL:         ttl,
				}
				ttl += 1
				retry = 0
			}

			if ttl > t.options.maxHops {
				result <- models.TraceResult{
					Addr:        fmt.Sprintf("%v.%v.%v.%v", destAddr[0], destAddr[1], destAddr[2], destAddr[3]),
					Unreachable: true,
				}
				break
			}
			continue
		}

		address := from.(*syscall.SockaddrInet4).Addr

		hop := Hop{
			Id:          id,
			Destination: dest,
			Success:     true,
			Address:     address,
			Host:        "",
			ElapsedTime: elapsed,
			TTL:         ttl,
		}

		hopHost, err := net.LookupAddr(hop.AddressString())

		if err == nil {
			hop.Host = hopHost[0]
		}

		c <- hop

		ttl += 1
		retry = 0

		if ttl > t.options.maxHops || address == destAddr {
			result <- models.TraceResult{
				Addr:        fmt.Sprintf("%v.%v.%v.%v", destAddr[0], destAddr[1], destAddr[2], destAddr[3]),
				Unreachable: false,
			}
			break
		}
	}
	return nil
}
