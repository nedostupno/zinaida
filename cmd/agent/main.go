package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/nedostupno/zinaida/proto/manager"
	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:22842", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	c := manager.NewManagerClient(conn)
	r := &manager.RegistrateRequest{}
	domain := os.Getenv("DOMAIN_AGENT")
	ip := os.Getenv("IP_AGENT")

	if domain == "" {
		r.Node = &manager.RegistrateRequest_Ip{ip}
	} else {
		r.Node = &manager.RegistrateRequest_Domain{domain}
	}

	resp, err := Registrate(context.Background(), c, r)
	if err != nil {
		log.Println("Yps...... Nice Error: ", err)
	}

	fmt.Println(resp)
}

func Registrate(ctx context.Context, c manager.ManagerClient, r *manager.RegistrateRequest) (*manager.RegistrateResponse, error) {
	response, err := c.Registrate(ctx, r)
	if err != nil {
		return response, err
	}
	return response, nil
}
