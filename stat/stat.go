package stat

import (
	"bytes"
	"io"
	"log"
	"os/exec"

	"github.com/nedostupno/zinaida/internal/models"
)

func GetLA() (string, error) {
	cmd := exec.Command("uptime")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()

	var l []string
	var la string
	var r byte = '\u000a'

	for {

		o, err := out.ReadString(r)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatalln(err)
			}
		}
		l = append(l, o)
	}

	la = l[0]
	return la, nil
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
