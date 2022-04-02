package stat

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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
	/*
		Blocks - общее количество блоков данных в файловой системе

		Bfree - количество свободных блоков на диске

		Bavail - количесвто свободных блоков доступных для не суперпользователей

		Files - сколько всего inode

		Ffree - сколько свободных inode

		Для понимания может помочь следущая иллюстрация:

		-------------------------------------------------------------------

		|<--------------------- Blocks ---------------------------------->|
						|<---------------- Bfree ------------------------>|

		 -----------------------------------------------------------------
		| USED          | Bavail                | Reserved for root 	 |
		-----------------------------------------------------------------
	*/
	d := new(Disk)
	bsize := statfs.Bsize
	d.Total = statfs.Blocks * uint64(bsize)
	d.Used = (statfs.Blocks - statfs.Bfree) * uint64(bsize)
	d.InodesTotal = statfs.Files
	d.InodesUsed = statfs.Files - statfs.Ffree

	return d, nil
}

type CPUStat struct {
	Cpu       string
	User      uint64
	Nice      uint64
	System    uint64
	Idle      uint64
	IOWait    uint64
	IRQ       uint64
	SoftIRQ   uint64
	Steal     uint64
	Guest     uint64
	GuestNice uint64
}

type CPUPercents struct {
	Cpu     string
	Usage   float64
	User    float64
	Nice    float64
	System  float64
	Idle    float64
	IOWait  float64
	IRQ     float64
	SoftIRQ float64
	Steal   float64
}

func GetCPUInfo() ([]CPUStat, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := []string{}

	CPUs, err := ParseCPUStatFile(file, &lines)
	if err != nil {
		return nil, err
	}

	return CPUs, nil
}

func ParseCPUStatFile(file *os.File, lines *[]string) ([]CPUStat, error) {
	// Получаем слайс строк со всеми строками из файла /proc/stat, которые начинаются с cpu
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu") {
			*lines = append(*lines, line)
		}
	}

	CPUs := []CPUStat{}

	for _, line := range *lines {

		var stat CPUStat
		fields := strings.Fields(line)

		err := parseCPUFields(fields, &stat)
		if err != nil {
			return nil, err
		}

		CPUs = append(CPUs, stat)
	}

	return CPUs, nil
}

func parseCPUFields(fields []string, stat *CPUStat) error {
	var err error
	stat.Cpu = fields[0]
	if stat.Cpu == "cpu" {
		stat.Cpu = "cpu total"
	}
	stat.User, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return err
	}
	stat.Nice, err = strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return err
	}
	stat.System, err = strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return err
	}
	stat.Idle, err = strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return err
	}
	stat.IOWait, err = strconv.ParseUint(fields[5], 10, 64)
	if err != nil {
		return err
	}
	stat.IRQ, err = strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return err
	}
	stat.SoftIRQ, err = strconv.ParseUint(fields[7], 10, 64)
	if err != nil {
		return err
	}
	return nil
}

func GetCPUPercent() ([]CPUPercents, error) {
	cpuTimes1, err := GetCPUInfo()
	if err != nil {
		return nil, err
	}

	time.Sleep(time.Second)

	cpuTimes2, err := GetCPUInfo()
	if err != nil {
		return nil, err
	}

	perc, err := calculateCPUPercent(cpuTimes1, cpuTimes2)
	if err != nil {
		return nil, err
	}

	return perc, nil
}

func calculateCPUPercent(t1, t2 []CPUStat) ([]CPUPercents, error) {

	var percents []CPUPercents
	for i := 0; i < len(t1); i++ {

		var c CPUPercents
		c.Cpu = t1[i].Cpu

		user := t2[i].User
		prevUser := t1[i].User

		system := t2[i].System
		prevSystem := t1[i].System

		nice := t2[i].Nice
		prevNice := t1[i].Nice

		irq := t2[i].IRQ
		prevIrq := t1[i].IRQ

		softIrq := t2[i].SoftIRQ
		prevSoftIrq := t1[i].SoftIRQ

		steal := t2[i].Steal
		prevSteal := t1[i].Steal

		idle := t2[i].Idle
		prevIdle := t1[i].Idle

		iowait := t2[i].IOWait
		prevIowait := t1[i].IOWait

		prevTotal := prevUser + prevSystem + prevNice + prevIrq + prevSoftIrq + prevSteal + prevIdle + prevIowait
		total := user + system + nice + irq + softIrq + steal + idle + iowait

		totald := total - prevTotal

		userPercent := (float64(user) - float64(prevUser)) / float64(totald) * float64(100)
		nicePercent := (float64(nice) - float64(prevNice)) / float64(totald) * float64(100)
		systemPercent := (float64(system) - float64(prevSystem)) / float64(totald) * float64(100)
		irqPercent := (float64(irq) - float64(prevIrq)) / float64(totald) * float64(100)
		softIrqPercent := (float64(softIrq) - float64(prevSoftIrq)) / float64(totald) * float64(100)
		stealPercent := (float64(steal) - float64(prevSteal)) / float64(totald) * float64(100)
		idlePercent := (float64(idle) - float64(prevIdle)) / float64(totald) * float64(100)
		usagePercent := (float64(totald) - (float64(idle) - float64(prevIdle))) / float64(totald) * float64(100)

		// Округляем полученные значения до сотых
		c.User = math.Round(userPercent*100) / 100
		c.Nice = math.Round(nicePercent*100) / 100
		c.System = math.Round(systemPercent*100) / 100
		c.IRQ = math.Round(irqPercent*100) / 100
		c.SoftIRQ = math.Round(softIrqPercent*100) / 100
		c.Steal = math.Round(stealPercent*100) / 100
		c.Idle = math.Round(idlePercent*100) / 100
		c.Usage = math.Round(usagePercent*100) / 100

		percents = append(percents, c)
	}

	return percents, nil
}

type TopProc struct {
	Process []Process `json:"procs"`
}

type Process struct {
	User    string  `json:"user,omitempty"`
	PID     uint64  `json:"pid,omitempty"`
	CPU     float64 `json:"cpu,omitempty"`
	MEM     float64 `json:"mem,omitempty"`
	VSZ     uint64  `json:"vsz,omitempty"`
	RSS     uint64  `json:"rss,omitempty"`
	TTY     string  `json:"tty,omitempty"`
	Stat    string  `json:"stat,omitempty"`
	Start   string  `json:"start,omitempty"`
	Time    string  `json:"time,omitempty"`
	Command string  `json:"command,omitempty"`
}

func GetTopProc() (*TopProc, error) {

	top := new(TopProc)

	output, err := top.execPs()
	if err != nil {
		return nil, err
	}

	err = top.ParsePsOutput(output)
	if err != nil {
		return nil, err
	}

	return top, nil
}

func (t *TopProc) execPs() (*bytes.Buffer, error) {
	ps := exec.Command("ps", "aux", "--sort", "-pcpu")
	var stdout bytes.Buffer
	ps.Stdout = &stdout
	ps.Run()

	head := exec.Command("head", "-6")
	var output bytes.Buffer
	head.Stdin = &stdout
	head.Stdout = &output
	head.Run()

	return &output, nil
}

func (t *TopProc) ParsePsOutput(output *bytes.Buffer) error {
	var r byte = '\u000a'

	for {
		p := Process{}
		o, err := output.ReadString(r)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatalln(err)
			}
		}

		fields := strings.Fields(o)
		if fields[0] == "USER" {
			continue
		}
		p.User = fields[0]
		p.PID, err = strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return err
		}
		p.CPU, err = strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return err
		}
		p.MEM, err = strconv.ParseFloat(fields[3], 64)
		if err != nil {
			return err
		}
		p.VSZ, err = strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return err
		}
		p.RSS, err = strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return err
		}
		p.TTY = fields[6]
		p.Stat = fields[7]
		p.Start = fields[8]
		p.Time = fields[9]
		p.Command = fields[10]

		t.Process = append(t.Process, p)
	}
	return nil
}
