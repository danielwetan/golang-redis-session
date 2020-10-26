package helpers

type Response struct {
	Status bool        `json:"status"`
	Body   interface{} `json:"body"`
}

func ResponseMsg(status bool, body interface{}) *Response {
	res := &Response{
		Status: status,
		Body:   body,
	}
	return res
}
