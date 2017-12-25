package mineme

import (
	"errors"
	"time"

	"gopkg.in/mgo.v2"
)

// var checkPassword = regexp.MustCompile(`^[a-zA-Z0-9_\-\*!@#$%^&()+=\[\]\{\}]{6,15}$`)

//ErrDBIsNil error handler
var ErrDBIsNil = errors.New("Pointer to database is null")

// var _ ManipulateData = (*Model)(nil)

//Model is a current state of application data
type Model struct {
	db *mgo.Database
}

//Close connection to mongoDB
func (m *Model) Close() {
	m.db.Session.Close()
}

//NewModel opens connection to database and returns a new model
func NewModel(conn string, dbname string) (*Model, error) {
	s, err := mgo.DialWithTimeout(conn, time.Minute*2)
	if err != nil {
		return nil, err
	}
	db := s.DB(dbname)
	return &Model{db: db}, nil
}

//Create a user
func (m *Model) Create(u *User) error {
	return u.Create(m.db)
}

//Read a user. OID must be specified before request
func (m *Model) Read(u *User) error {
	return u.Read(m.db)
}

//Update a user with new values
func (m *Model) Update(u *User) error {
	return u.Update(m.db)
}

//Delete a user from database
func (m *Model) Delete(u *User) error {
	return u.Delete(m.db)
}

//AuthUser using login and password
func (m *Model) AuthUser(u *User) error {
	return u.FindUser(m.db)
}
