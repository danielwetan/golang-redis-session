package helpers

var Query = map[string]string{
	"login":    "SELECT * FROM users WHERE username = ?",
	"register": "INSERT INTO users (username, password) VALUES (?, ?)",
}
