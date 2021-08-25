package traceroute

import (
	"bytes"
	"io"
	"os/exec"
)

func Traceroute(i []string) ([]string, error) {
	var output []string

	for _, ip := range i {
		cmd := exec.Command("tracepath", ip, "-4")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()

		var r byte = '\u000a'

		for {

			o, err := out.ReadString(r)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					return nil, err
				}
			}
			output = append(output, o)
		}
	}
	return output, nil
}
