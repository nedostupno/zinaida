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
	// Получаем слайс ip адресов интерфейсах не сервере
	ips, err := net.InterfaceAddrs()
	if err != nil {
		return [4]byte{}, err
	}

	// В слайсе полученных ip адресов находим первый ip, который
	// не является loopback адресом или IPv6, а затем
	// возвращаем его в виде 4-х байтного массива
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
	// Получаем ip адрес из ресурных записей домена.
	// Если dest уже является ip, то функция все равно отработает корретно
	// и вернут слайс с одним элементом, которым и будует переданный ip
	ips, err := net.LookupHost(dest)
	if err != nil {
		return [4]byte{}, err
	}

	// Приводим первый ip из нашего слайса, который является типом string к типу *net.IPAddr
	ip, err := net.ResolveIPAddr("ip", ips[0])
	if err != nil {
		return [4]byte{}, err
	}
	destAddr := [4]byte{}
	// Возвращаем полученный ip в виде 4-х байтного массива
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

		// Устанавливаем ttl для отправяляющего сокета
		syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
		// Устанавливаем время ожидания для слушающего сокета
		syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: t.options.port, Addr: socketAddr})
		syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: t.options.port, Addr: destAddr})

		var p = make([]byte, t.options.packetSize)
		_, from, err := syscall.Recvfrom(recvSocket, p, 0)
		elapsed := time.Since(start)

		// Ошибку мы можем получить в случае, когда время ожидания на слушающем сокете истекло
		if err != nil {
			retry += 1

			// Если количество попыток для конкретного хопа истекло, то
			// мы отправялем информацию о том, что на данном хопе мы не получили ответ и
			// переходим к следующему хопу
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

			// Если мы не получаем ответа на хопе и при этом ttl уже достиг своего максимума установленного в конфиге,
			// то мы сообщаем в канал result о том, что нам не удалось построить трассировку до ноды-агента,
			// выходим из цикла и завершаем исполнение
			if ttl > t.options.maxHops {
				result <- models.TraceResult{
					Addr:        fmt.Sprintf("%v.%v.%v.%v", destAddr[0], destAddr[1], destAddr[2], destAddr[3]),
					Unreachable: true,
				}
				break
			}
			// Если ttl не достиг своего максимума, мы просто переходим к следующей итерации цикла
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
