package mineme

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var _ CRUD = (*Session)(nil)

//SessionContext stores data for context
type SessionContext string

//SESSIONCOLLECTION Collection name in mongodb
const SESSIONCOLLECTION = "sessions"

//Session describes the current session from the browser.
type Session struct {
	OID       bson.ObjectId `json:"-,omitempty" mgo:"_oid"`
	SessionID uuid.UUID     `json:"session_id,omitempty" mgo:"session_id"`
	UserID    uuid.UUID     `json:"user_id,omitempty" mgo:"user_id"`
	Lifetime  int64
	Created   int64
	mux       sync.RWMutex
	user      *User
}

//Errors handling for sessions
var (
	ErrUserIDIsNull = errors.New("User ID can't be null")
)

//NewSession creates a new session, uploads it to database and returns object info
func NewSession(userid uuid.UUID, Lifetime int64, db *mgo.Database) (*Session, error) {
	if db == nil {
		return nil, ErrDBIsNil
	}
	if userid == uuid.Nil {
		return nil, ErrUserIDIsNull
	}
	s := &Session{
		OID:      bson.NewObjectId(),
		UserID:   userid,
		Lifetime: Lifetime,
		Created:  time.Now().Unix(),
	}
	if err := s.Create(db); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) String() string {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.Created+s.Lifetime < time.Now().Unix() {
		return fmt.Sprintf("Session [%s] is expired", s.SessionID)
	}
	return fmt.Sprintf("Session [%s]. Expiration date: %s", s.SessionID, time.Unix(s.Created+s.Lifetime, 0))
}

//Create a new session and upload it to database
func (s *Session) Create(db *mgo.Database) error {
	coll := db.C(SESSIONCOLLECTION)
	for {
		n, err := coll.FindId(s.OID).Count()
		if err != nil {
			return err
		}
		if n > 0 {
			s.OID = bson.NewObjectId()
			continue
		}
		break
	}
	return nil
}

//Read a specified session from database
func (s *Session) Read(db *mgo.Database) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	return db.C(SESSIONCOLLECTION).FindId(s.OID).One(s)
}

//ReadUUID read from database with specified SessionID
func (s *Session) ReadUUID(db *mgo.Database) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	return db.C(SESSIONCOLLECTION).Find(bson.M{"session_id": s.SessionID.String()}).One(s)
}

//Update current session at the backend server and in the database
func (s *Session) Update(db *mgo.Database) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if db == nil {
		return ErrDBIsNil
	}
	return db.C(SESSIONCOLLECTION).UpdateId(s.OID, s)
}

//Delete session from database
func (s *Session) Delete(db *mgo.Database) error {
	return db.C(SESSIONCOLLECTION).RemoveId(s.OID)
}

//User retrieves user from database assosiated with current session
func (s *Session) User(db *mgo.Database) (*User, error) {
	if s.user != nil {
		return s.user, nil
	}
	u := &User{ID: s.UserID}
	err := db.C(USERCOLLECTION).Find(bson.M{"id": u}).One(u)
	s.user = u
	return u, err
}
