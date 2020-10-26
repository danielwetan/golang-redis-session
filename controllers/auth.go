package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/danielwetan/golang-redis-session/models"

	"github.com/danielwetan/golang-redis-session/helpers"
)

func Register(w http.ResponseWriter, r *http.Request) {
	helpers.Headers(&w)

	if r.Method == "POST" {
		r.ParseForm()

		db, err := helpers.Connect()
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer db.Close()

		username, password := r.FormValue("username"), r.FormValue("password")
		hashedPassword, _ := helpers.HashPassword(password)
		register := &models.Register{
			Username: username,
			Password: hashedPassword,
		}

		_, err = db.Exec(helpers.Query["register"], register.Username, register.Password)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		body := "Register success"
		res := helpers.ResponseMsg(true, body)
		json.NewEncoder(w).Encode(res)
	} else {
		body := "Invalid HTTP method"
		res := helpers.ResponseMsg(false, body)
		json.NewEncoder(w).Encode(res)
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	helpers.Headers(&w)

	if r.Method == "POST" {
		r.ParseForm()

		db, err := helpers.Connect()
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer db.Close()

		var login = models.Login{}
		username, password := r.FormValue("username"), r.FormValue("password")
		err = db.
			QueryRow(helpers.Query["login"], username).
			Scan(&login.Username, &login.Password)
		if err != nil {
			// If now rows in result set
			fmt.Println(err.Error())
			res := helpers.ResponseMsg(false, err.Error())
			json.NewEncoder(w).Encode(res)
			return
		}

		match := helpers.CheckPasswordHash(password, login.Password)
		if match {
			// Create a new random session token
			sessionToken := uuid.NewV4().String()
			//Set the token in the cache, along with the user whom it represents
			// The token has an expirt time of 120 seconds
			_, err = helpers.InitCache().Do("SETEX", sessionToken, "120", username)
			if err != nil {
				// If there is an error in setting the cache, return an internal server error
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Finally, we set the client cookie for "session_token" as the session token we just generated
			// We also set an expiry time of 120 seconds, the same as the cache
			http.SetCookie(w, &http.Cookie{
				Name:    "session_token",
				Value:   sessionToken,
				Expires: time.Now().Add(120 * time.Second),
			})

			res := helpers.ResponseMsg(true, login)
			json.NewEncoder(w).Encode(res)
		} else {
			body := "Username or password is wrong"
			res := helpers.ResponseMsg(false, body)
			json.NewEncoder(w).Encode(res)
		}
	} else {
		body := "Invalid HTTP method"
		res := helpers.ResponseMsg(false, body)
		json.NewEncoder(w).Encode(res)
	}
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// We can obtain the session token from the request cookies, which come with every request
		c, err := r.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusBadRequest)

				res := helpers.ResponseMsg(false, string(err.Error()))
				json.NewEncoder(w).Encode(res)

				return
			}
			sessionToken := c.Value

			// We then get the name of the user from our cache, where we set the session token
			response, err := helpers.InitCache().Do("GET", sessionToken)
			if err != nil {
				// If there is an error when fetching from cache, return an internal server error status
				w.WriteHeader(http.StatusInternalServerError)
				res := helpers.ResponseMsg(false, string(err.Error()))
				json.NewEncoder(w).Encode(res)
				return
			}

			if response == nil {
				// If the session token is not present in cache, return an unathorized error
				w.WriteHeader(http.StatusUnauthorized)
				res := helpers.ResponseMsg(false, string(err.Error()))
				json.NewEncoder(w).Encode(res)
				return
			}
		}
		body := "Valid Cookies, welcome user!"
		res := helpers.ResponseMsg(true, body)
		json.NewEncoder(w).Encode(res)
	} else {
		body := "Invalid HTTP method"
		res := helpers.ResponseMsg(false, body)
		json.NewEncoder(w).Encode(res)
	}
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// We can obtain the session token from the request cookies, which come with every request
		c, err := r.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusBadRequest)

				res := helpers.ResponseMsg(false, string(err.Error()))
				json.NewEncoder(w).Encode(res)
				return
			}
		}
		sessionToken := c.Value

		// We then get the name of the user from our cache, where we set the session token
		response, err := helpers.InitCache().Do("GET", sessionToken)
		if err != nil {
			// If there is an error when fetching from cache, return an internal server error status
			w.WriteHeader(http.StatusInternalServerError)
			res := helpers.ResponseMsg(false, string(err.Error()))
			json.NewEncoder(w).Encode(res)
			return
		}

		if response == nil {
			// If the session token is not present in cache, return an unathorized error
			w.WriteHeader(http.StatusUnauthorized)
			res := helpers.ResponseMsg(false, string(err.Error()))
			json.NewEncoder(w).Encode(res)
			return
		}

		// Create new sesion token for the current user
		newSessionToken := uuid.NewV4().String() + "New"
		_, err = helpers.InitCache().Do("SETEX", newSessionToken, "120", fmt.Sprintf("%s", response))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			res := helpers.ResponseMsg(false, string(err.Error()))
			json.NewEncoder(w).Encode(res)
			return
		}

		// Delete the older session token
		_, err = helpers.InitCache().Do("DEL", sessionToken)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			res := helpers.ResponseMsg(false, string(err.Error()))
			json.NewEncoder(w).Encode(res)
			return
		}

		// Set the new token as the users `session_token` cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   newSessionToken,
			Expires: time.Now().Add(120 * time.Second),
		})

		body := "Refresh cookies"
		res := helpers.ResponseMsg(true, body)
		json.NewEncoder(w).Encode(res)
	} else {
		body := "Invalid HTTP method"
		res := helpers.ResponseMsg(false, body)
		json.NewEncoder(w).Encode(res)
	}
}
