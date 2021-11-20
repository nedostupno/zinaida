package stat

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/nedostupno/zinaida/internal/models"
	"golang.org/x/sys/unix"
)

type LA struct {
	One     float64 `json:"one,omitempty"`
	Five    float64 `json:"five,omitempty"`
	Fifteen float64 `json:"fifteen,omitempty"`
}

func GetLA() (*LA, error) {
	la := new(LA)
	fields, err := la.readLoadAvarageFile()
	if err != nil {
		return nil, err
	}

	err = la.parseFields(fields)
	if err != nil {
		return nil, err
	}

	return la, nil
}

func (la *LA) readLoadAvarageFile() ([]string, error) {
	file, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(bytes.NewBuffer(file))

	line, _, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(line))
	return fields, nil
}

func (la *LA) parseFields(fields []string) error {
	var err error

	la.One, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return err
	}

	la.Five, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return err
	}

	la.Fifteen, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return err
	}
	return nil
}

type Mem struct {
	Total     uint64 `json:"total,omitempty"`
	Used      uint64 `json:"used,omitempty"`
	Free      uint64 `json:"free,omitempty"`
	Buffers   uint64 `json:"buffers,omitempty"`
	Cache     uint64 `json:"cache,omitempty"`
	SwapTotal uint64 `json:"swap_total,omitempty"`
	SwapUsed  uint64 `json:"swap_used,omitempty"`
	SwapFree  uint64 `json:"swap_free,omitempty"`
}

func GetMemInfo() (*Mem, error) {
	mem := new(Mem)

	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	mem.parseStatFile(file)

	return mem, nil
}

func (m *Mem) parseStatFile(file *os.File) error {
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		err := m.parseFields(fields)
		if err != nil {
			return err
		}
	}

	m.Used = m.Total - m.Free - m.Buffers - m.Cache
	m.SwapUsed = m.SwapTotal - m.SwapFree

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (m *Mem) parseFields(fields []string) error {
	fieldName := fields[0]

	value, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return err
	}

	switch fieldName {
	case "Buffers:":
		m.Buffers = value
	case "Cached:":
		m.Cache = value
	case "MemTotal:":
		m.Total = value
	case "MemFree:":
		m.Free = value
	case "SwapTotal:":
		m.SwapTotal = value
	case "SwapFree:":
		m.SwapFree = value
	}
	return nil
}

type Disk struct {
	Total       uint64
	Used        uint64
	InodesTotal uint64
	InodesUsed  uint64
}

func GetDiskInfo(path string) (*Disk, error) {
	statfs := new(unix.Statfs_t)
	err := unix.Statfs(path, statfs)
	if err != nil {
		return nil, err
	}

	// Blocks - общее количество блоков данных в файловой системе
	//
	// Bfree - количество свободных блоков на диске
	//
	// Bavail - количесвто свободных блоков доступных для не суперпользователей
	//
	// Files - сколько всего inode
	//
	// Ffree - сколько свободных inode
	//
	// Для понимания может помочь следущая иллюстрация:
	//
	//--------------------------------------------------------------------
	//
	// |<--------------------- Blocks ------------------------------->|
	// 					|<---------------- Bfree ------------------->|
	//
	// ---------------------------------------------------------------
	// | USED          | Bavail                | Reserved for root 	 |
	// ---------------------------------------------------------------

	d := new(Disk)
	bsize := statfs.Bsize
	d.Total = statfs.Blocks * uint64(bsize)
	d.Used = (statfs.Blocks - statfs.Bfree) * uint64(bsize)
	d.InodesTotal = statfs.Files
	d.InodesUsed = statfs.Files - statfs.Ffree

	return d, nil
}

func GetCpuInfo() (models.CPU, error) {
	cmd := exec.Command("lscpu")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()

	var r byte = '\u000a'

	var cpu []string
	for {

		o, err := out.ReadString(r)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatalln(err)
			}
		}
		cpu = append(cpu, o)
	}

	var c models.CPU
	var err error

	c.Max_MHz = cpu[16]
	if err != nil {
		log.Fatalln(err)
	}
	c.Min_MHz = cpu[17]
	if err != nil {
		log.Fatalln(err)
	}
	c.Cpu_s = cpu[4]
	if err != nil {
		log.Fatalln(err)
	}
	c.Model = cpu[13]

	return c, nil
}

func GetTopProc() (models.TopProc, error) {

	var topProc models.TopProc

	cmd1 := exec.Command("ps", "aux", "--sort", "-pcpu")
	var out bytes.Buffer
	cmd1.Stdout = &out
	cmd1.Run()

	cmd2 := exec.Command("head", "-5")
	var output bytes.Buffer
	cmd2.Stdin = &out
	cmd2.Stdout = &output
	cmd2.Run()

	var r byte = '\u000a'

	var top []string
	for {

		o, err := output.ReadString(r)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatalln(err)
			}
		}
		top = append(top, o)
	}

	topProc.First = top[0]
	topProc.Second = top[1]
	topProc.Third = top[2]
	topProc.Fourth = top[3]
	topProc.Fifth = top[4]

	return topProc, nil
}
