package mineme

import (
	"crypto/md5"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/google/uuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var _ CRUD = (*User)(nil)

//USERCOLLECTION unifies name of the user collection
const USERCOLLECTION = "users"

//Compiled regexpressions for checking user parameters
var (
	checkNames    = regexp.MustCompile(`^[A-Za-z0-9]+(?:[ _-][A-Za-z0-9]+)*$`)
	checkLogin    = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,15}$`)
	checkPassword = regexp.MustCompile(`^[\S]{6,15}$`)
)

//Errors handling
var (
	ErrWrongInput    = errors.New("Input is wrong")
	ErrTooShortInput = errors.New("Input is too short")
	ErrLoginExists   = errors.New("Login is already taken")
)

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
	return fmt.Sprintf("[%s] %s %s at the age of %d", u.ID, u.LastName, u.FirstName, u.Age)
}

//MakeSafeUser creates version for public views
func (u *User) MakeSafeUser() *SafeUserDetails {
	s := &SafeUserDetails{}
	s.ApplyUser(u)
	return s
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
	return coll.Insert(u)
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

//ReadUUID reads user info from database. OID should be specified before request
func (u *User) ReadUUID(db *mgo.Database) error {
	u.mux.Lock()
	defer u.mux.Unlock()
	return db.C(USERCOLLECTION).Find(bson.M{"id": u.ID.String()}).One(u)
}

//FindUser using user and password
func (u *User) FindUser(db *mgo.Database) error {
	// return db.C(USERCOLLECTION).Find(bson.M{
	// 	"login":    u.Login,
	// 	"password": u.Password,
	// }).One(&u)
	if bson.IsObjectIdHex(u.OID.String()) {
		logger.Printf("Using OID to find user: %s", u.OID.String())
		return db.C(USERCOLLECTION).FindId(u.OID).Limit(1).One(u)
	} else if u.ID != uuid.Nil {
		logger.Printf("Using UUID to find user: %s", u.ID.String())
		return db.C(USERCOLLECTION).Find(bson.M{"id": u.ID}).Limit(1).One(u)
	}
	logger.Printf("Using login & password to find user: %s", u.Login)
	return db.C(USERCOLLECTION).Find(bson.M{"login": u.Login, "password": u.Password}).Limit(1).One(u)
}

//NewUser creates a new user
func NewUser(FirstName, LastName, Login, Password string, Age int, Group Group, Status Status, db *mgo.Database) (*User, error) {
	if db == nil {
		return nil, ErrDBIsNil
	}
	if !checkNames.MatchString(FirstName) || !checkNames.MatchString(LastName) {
		return nil, fmt.Errorf("FirstName or LastName error: %s %s", FirstName, LastName)
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
		Login:     Login,
		ID:        uuid.New(),
		FirstName: FirstName,
		LastName:  LastName,
		Password:  encryptedPassword,
		Age:       Age,
		Group:     Group,
	}
	if err := u.Create(db); err != nil {
		return nil, err
	}
	return u, nil
}

//IsExist checks if user exist or not
func (u *User) IsExist(db *mgo.Database) bool {
	var n int
	var err error
	if bson.IsObjectIdHex(u.OID.String()) {
		logger.Printf("Using OID to find user: %s", u.OID.String())
		n, err = db.C(USERCOLLECTION).FindId(u.OID).Limit(1).Count()
	} else if u.ID != uuid.Nil {
		logger.Printf("Using UUID to find user: %s", u.ID.String())
		n, err = db.C(USERCOLLECTION).Find(bson.M{"id": u.ID}).Limit(1).Count()
	} else {
		logger.Printf("Using login & password to find user: %s", u.Login)
		n, err = db.C(USERCOLLECTION).Find(bson.M{"login": u.Login, "password": u.Password}).Limit(1).Count()
	}

	if err != nil || n == 0 {
		return false
	}
	return true
}

//IsLoginExist checks of availability of login
func (u *User) IsLoginExist(db *mgo.Database) bool {
	var n int
	var err error
	{
		logger.Printf("Using login to find user: %s", u.Login)
		n, err = db.C(USERCOLLECTION).Find(bson.M{"login": u.Login}).Limit(1).Count()
	}
	if err != nil || n == 0 {
		return false
	}
	return true
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
