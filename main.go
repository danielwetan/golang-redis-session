package main

import (
	"fmt"
	"net/http"

	"github.com/danielwetan/golang-redis-session/routes"
)

func main() {

	routes.Auth()

	PORT := ":3000"
	fmt.Println("App running on PORT", PORT)
	err := http.ListenAndServe(PORT, nil)
	if err != nil {
		fmt.Println(err.Error())
	}
}
