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
)

type LA struct {
	One     float64
	Five    float64
	Fifteen float64
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
