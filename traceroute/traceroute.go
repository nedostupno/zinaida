package traceroute

import (
	"bytes"
	"io"
	"os/exec"
)

type Traceroute struct {
	Trace []string
}
type Result struct {
	Traceroute []Traceroute
}

func Trace(i []string) (Result, error) {
	var trace Traceroute
	var res Result

	for _, ip := range i {
		cmd := exec.Command("tracepath", ip, "-4")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		var output []string

		var r byte = '\u000a'

		for {

			o, err := out.ReadString(r)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					return Result{}, err
				}
			}
			output = append(output, o)
		}
		trace.Trace = output
		res.Traceroute = append(res.Traceroute, trace)
	}
	return res, nil
}
