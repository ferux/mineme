package mineme

//SafeUserDetails used for response to client useful user information without compromate password
type SafeUserDetails struct {
	ID              string `json:"id,omitempty"`
	Login           string `json:"login,omitempty"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	Description     string `json:"description,omitempty" bson:"description"`
	Age             int    `json:"age,omitempty" bson:"age"`
	Hashes          int    `json:"hashes,omitempty" bson:"hashes"`
	AcceptedHashes  int    `json:"accepted_hashes,omitempty" bson:"accepted_hashes"`
	PaymentsDone    int    `json:"payments_done,omitempty" bson:"payments_done"`
	PaymentsPending int    `json:"payments_pending,omitempty" bson:"payments_pending"`
	PaymentsAll     int    `json:"payments_all,omitempty" bson:"payments_all"`
}

//ApplyUser to public view
func (s *SafeUserDetails) ApplyUser(u *User) {
	if u == nil {
		return
	}
	s.ID = u.ID.String()
	s.Login = u.Login
	s.FirstName = u.FirstName
	s.LastName = u.LastName
	s.Description = u.Description
	s.Age = u.Age
	s.Hashes = u.Hashes
	s.AcceptedHashes = u.AcceptedHashes
	s.PaymentsDone = u.PaymentsDone
	s.PaymentsAll = u.PaymentsAll
	s.PaymentsPending = u.PaymentsPending
}

//NewSafeUser creates a new user by copying values from original User struct
func NewSafeUser(u *User) *SafeUserDetails {
	if u == nil {
		return nil
	}
	s := &SafeUserDetails{}
	s.ApplyUser(u)
	return s
}
