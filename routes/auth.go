package routes

import (
	"net/http"

	"github.com/danielwetan/golang-redis-session/controllers"
)

func Auth() {
	http.HandleFunc("/auth/register", controllers.Register)
	http.HandleFunc("/auth/login", controllers.Login)
	http.HandleFunc("/auth", controllers.Welcome)
	http.HandleFunc("/auth/refresh", controllers.Refresh)
}
