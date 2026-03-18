package output

type Result struct {
	URL           string   `json:"url"`
	Tech          string   `json:"tech,omitempty"`
	HasParams     bool     `json:"has_params"`
	IsSecret      bool     `json:"is_secret,omitempty"`
	EntropyParams []string `json:"entropy_params,omitempty"`
	OutOfScope    bool     `json:"-"`
}
