package mineme

import (
	"crypto/md5"
	"errors"
	"io"
	"io/ioutil"
	"log"

	"gopkg.in/mgo.v2"
)

// var checkPassword = regexp.MustCompile(`^[a-zA-Z0-9_\-\*!@#$%^&()+=\[\]\{\}]{6,15}$`)

//ErrDBIsNil error handler
var ErrDBIsNil = errors.New("Pointer to database is null")
var logger *log.Logger

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
func NewModel(db *mgo.Database, debug bool, debugW io.Writer) (*Model, error) {

	if db == nil {
		return nil, ErrDBIsNil
	}
	if debug {
		logger = log.New(debugW, "[Model] ", log.Ldate+log.Ltime)
	} else {
		logger = log.New(ioutil.Discard, "", 0)
	}
	return &Model{db: db}, nil
}

//Create a user
func (m *Model) Create(u *User) error {
	logger.Printf("Creating new user: %s", u.Login)
	return u.Create(m.db)
}

//Read a user. OID must be specified before request
func (m *Model) Read(u *User) error {
	logger.Printf("Reading user with the following OID: %s", u.OID.String())
	return u.Read(m.db)
}

//ReadUUID a user. OID must be specified before request
func (m *Model) ReadUUID(u *User) error {
	logger.Printf("Reading user with the following UUID: %s", u.ID.String())
	return u.ReadUUID(m.db)
}

//Update a user with new values
func (m *Model) Update(u *User) error {
	logger.Printf("Updating user with the following OID: %s", u.OID.String())
	return u.Update(m.db)
}

//Delete a user from database
func (m *Model) Delete(u *User) error {
	logger.Printf("Deleting user with the following OID: %s", u.OID.String())
	return u.Delete(m.db)
}

//AuthUser using login and password
func (m *Model) AuthUser(u *User) error {
	logger.Printf("Finding user with the following credentials: %s:%s", u.Login, u.Password)
	return u.FindUser(m.db)
}

//CreateNewUser creates new user from login request
func (m *Model) CreateNewUser(login, password, fName, lName string, age int) (*User, error) {
	logger.Printf("Create user: %s %s (%s:%s), age %d", fName, lName, login, password, age)
	return NewUser(fName, lName, login, password, age, USER, USERNEW, m.db)
}

//CheckUserExists checks if user exists
func (m *Model) CheckUserExists(login, password string, u *User) bool {
	if u == nil {
		encryptedPassword := md5.Sum([]byte(password))
		u = &User{Login: login, Password: encryptedPassword}
	}
	return u.IsExist(m.db)
}
