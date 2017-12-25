package mineme

import (
	"crypto/md5"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var _ CRUD = (*User)(nil)

const USERCOLLECTION = "users"

var checkNames = regexp.MustCompile(`^[A-Za-z0-9]+(?:[ _-][A-Za-z0-9]+)*$`)
var checkLogin = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,15}$`)
var checkPassword = regexp.MustCompile(`^[\S]{6,15}$`)

//User is a representation of User data model
type User struct {
	OID             bson.ObjectId `json:"-,omitempty" bson:"_id"`
	ID              uuid.UUID     `json:"id,omitempty" bson:"id"`
	Login           string        `json:"login,omitempty" bson:"login"`
	FirstName       string        `json:"first_name,omitempty" bson:"first_name"`
	LastName        string        `json:"last_name,omitempty" bson:"last_name"`
	Password        [16]byte      `json:"password,omitempty" bson:"password"`
	Description     string        `json:"description,omitempty" bson:"description"`
	Age             int           `json:"age,omitempty" bson:"age"`
	Status          Status        `json:"status,omitempty" bson:"status"`
	Group           Group         `json:"group,omitempty" bson:"group"`
	Expired         time.Time     `json:"expired,omitempty" bson:"expired"`
	Hashes          int           `json:"hashes,omitempty" bson:"hashes"`
	AcceptedHashes  int           `json:"accepted_hashes,omitempty" bson:"accepted_hashes"`
	PaymentsDone    int           `json:"payments_done,omitempty" bson:"payments_done"`
	PaymentsPending int           `json:"payments_pending,omitempty" bson:"payments_pending"`
	PaymentsAll     int           `json:"payments_all,omitempty" bson:"payments_all"`
	mux             sync.RWMutex
}

func (u *User) String() string {
	u.mux.Lock()
	defer u.mux.Unlock()
	return fmt.Sprintf("[%s] %s %s", u.ID, u.LastName, u.FirstName)
}

//Update user in db and at backend
func (u *User) Update(db *mgo.Database) error {
	u.mux.Lock()
	defer u.mux.Unlock()
	if db == nil {
		return ErrDBIsNil
	}
	return db.C(USERCOLLECTION).UpdateId(u.OID, u)
}

//Create a user at database
func (u *User) Create(db *mgo.Database) error {
	coll := db.C(USERCOLLECTION)
	for {
		n, err := coll.FindId(u.OID).Count()
		if err != nil {
			return err
		}
		if n != 0 {
			u.OID = bson.NewObjectId()
			continue
		}
		break
	}
	return nil
}

//Delete deletes user from database
func (u *User) Delete(db *mgo.Database) error {
	return db.C(USERCOLLECTION).RemoveId(u.OID)
}

//Read reads user info from database. OID should be specified before request
func (u *User) Read(db *mgo.Database) error {
	u.mux.Lock()
	defer u.mux.Unlock()
	return db.C(USERCOLLECTION).FindId(u.OID).One(u)
}

//FindUser using user and password
func (u *User) FindUser(db *mgo.Database) error {
	u.mux.Lock()
	defer u.mux.Unlock()
	return db.C(USERCOLLECTION).Find(bson.M{
		"login":    u.Login,
		"password": u.Password,
	}).One(&u)
}

//Errors handling
var (
	ErrWrongInput    = errors.New("Input is wrong")
	ErrTooShortInput = errors.New("Input is too short")
)

//NewUser creates a new user
func NewUser(FirstName, LastName, Password, Login string, Age int, Group Group, Status Status, Expired time.Time, db *mgo.Database) (*User, error) {
	if db == nil {
		return nil, ErrDBIsNil
	}
	if !checkNames.MatchString(FirstName) || !checkNames.MatchString(LastName) ||
		!checkPassword.MatchString(Password) || !checkLogin.MatchString(Login) ||
		Age < 0 || Status < USERNEW || Status > USERPERMAMENTLY ||
		Group < OWNER || Group > GUEST {
		return nil, ErrWrongInput
	}
	if len(FirstName) < 1 || len(LastName) < 1 || len(Password) < 6 {
		return nil, ErrTooShortInput
	}
	encryptedPassword := md5.Sum([]byte(Password))
	u := &User{
		OID:       bson.NewObjectId(),
		ID:        uuid.New(),
		FirstName: FirstName,
		LastName:  LastName,
		Password:  encryptedPassword,
		Age:       Age,
		Group:     Group,
		Expired:   Expired,
	}
	if err := u.Create(db); err != nil {
		return nil, err
	}
	return u, nil
}

//Status describes the status of the account
type Status int

//Enum for status
const (
	USERNEW Status = iota
	USERAPPROVED
	USERPREMIUM
	USERTEMPORARY
	USERPERMAMENTLY
)

//Group describes the group of the account
type Group int

//Enum for group
const (
	OWNER Group = iota
	ADMINISTRATOR
	USER
	GUEST
)
