package main

import api "github.com/nedostupno/zinaida/internal/delivery"

func main() {
	a := api.Api{}
	a.Init()
	a.Run(":8000")
}
