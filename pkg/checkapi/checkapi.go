package checkapi

const (
	StatusAllowed    = "allowed"
	StatusBlocked    = "blocked"
	StatusProcessing = "processing"
)

type CheckRequest struct {
	Ecosystem string `json:"ecosystem"`
	Module    string `json:"module"`
	Version   string `json:"version"`
	Hash      string `json:"hash,omitempty"`
}

type CheckResponse struct {
	Status   string  `json:"status"`
	Reason   string  `json:"reason,omitempty"`
	Progress float64 `json:"progress,omitempty"`
	ID       string  `json:"id,omitempty"`
}
