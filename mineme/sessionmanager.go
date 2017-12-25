package mineme

import (
	"context"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

//SessionManager manages sessions
type SessionManager struct {
	cookieName  string
	maxlifetime int64
	db          *mgo.Database
	mux         sync.RWMutex
	logger      *log.Logger
}

//NewSessionManager creates a new instance of SM
func NewSessionManager(db *mgo.Database, debug bool, debugW io.Writer) (*SessionManager, error) {
	if db == nil {
		return nil, ErrDBIsNil
	}
	var logger *log.Logger
	if !debug {
		logger = log.New(ioutil.Discard, "", 0)
	} else {
		logger = log.New(debugW, "[SessionManager] ", log.Ldate+log.Ltime)
	}
	sm := &SessionManager{db: db, cookieName: "sessionid", logger: logger}
	sm.SessionGC()
	return sm, nil
}

func (s *SessionManager) sessionID() uuid.UUID {
	return uuid.New()
}

//SessionStart trying to retrieve session from cookies. If there is no cookies with session creates a new one
func (s *SessionManager) SessionStart(w http.ResponseWriter, r *http.Request) (*Session, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		sid := s.sessionID()
		sess := &Session{SessionID: sid, Lifetime: s.maxlifetime}
		if err != nil {
			return nil, err
		}
		cookie := &http.Cookie{
			Name:   s.cookieName,
			Value:  sid.String(),
			Path:   "/",
			MaxAge: int(s.maxlifetime),
		}
		http.SetCookie(w, cookie)
		ctx := context.WithValue(r.Context(), SessionContext("sessionid"), sid.String())
		r = r.WithContext(ctx)
		return sess, nil
	}
	var sess Session
	err = s.db.C(SESSIONCOLLECTION).Find(bson.M{"id": cookie.Value}).One(&sess)
	return &sess, err
}

//SessionEnd removes session from browser and database
func (s *SessionManager) SessionEnd(w http.ResponseWriter, r *http.Request) {
	s.mux.Lock()
	defer s.mux.Unlock()
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		return
	}
	hcookie := &http.Cookie{
		Name:     s.cookieName,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now(),
		MaxAge:   -1,
	}
	http.SetCookie(w, hcookie)
	s.db.C(SESSIONCOLLECTION).Remove(bson.M{"id": cookie.Value})
}

//SessionGC removes all expired sessions
func (s *SessionManager) SessionGC() {
	s.logger.Println("Garbage Collection initiated")
	s.db.C(SESSIONCOLLECTION).RemoveAll(bson.M{
		"created": bson.M{
			"$lte": time.Now().Unix(),
		},
	})
	time.AfterFunc(time.Minute*15, s.SessionGC)
}

//UpdateSession and save changes into db
func (s *SessionManager) UpdateSession(session *Session) error {
	return session.Update(s.db)
}

//LoadSessionUUID from database by Session_ID
func (s *SessionManager) LoadSessionUUID(session *Session) error {
	return session.ReadUUID(s.db)
}

//DeleteSession from database
func (s *SessionManager) DeleteSession(session *Session) error {
	return session.Delete(s.db)
}
