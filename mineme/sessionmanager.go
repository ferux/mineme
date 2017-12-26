package mineme

import (
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

var smlogger *log.Logger

//SessionManager manages sessions
type SessionManager struct {
	cookieName  string
	maxlifetime int64
	db          *mgo.Database
	mux         sync.RWMutex
}

//NewSessionManager creates a new instance of SM
func NewSessionManager(db *mgo.Database, debug bool, debugW io.Writer) (*SessionManager, error) {
	if db == nil {
		return nil, ErrDBIsNil
	}
	if !debug {
		smlogger = log.New(ioutil.Discard, "", 0)
	} else {
		smlogger = log.New(debugW, "[SessionManager] ", log.Ldate+log.Ltime)
	}
	sm := &SessionManager{db: db, cookieName: "sessionid", maxlifetime: int64(3600 * 24 * 10)}
	sm.SessionGC()
	return sm, nil
}

func (s *SessionManager) sessionID() uuid.UUID {
	return uuid.New()
}

//SessionStart trying to retrieve session from cookies. If there is no cookies with session creates a new one
func (s *SessionManager) SessionStart(w http.ResponseWriter, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		logger.Println("Cookie value is emptry")
		session := s.assignNewSession(w, r)
		return session, nil
	}
	logger.Printf("Found cookie with the following sessionid: %s", cookie.Value)
	logger.Println("Parsing cookie to UUID type")
	sUUID, err := uuid.Parse(cookie.Value)
	if err != nil {
		logger.Printf("Can't parse session UUID: %s", cookie.Value)
		return nil, err
	}
	session := &Session{SessionID: sUUID}
	err = session.FindByID(s.db)
	if err == mgo.ErrNotFound {
		logger.Println("Session not found")
		session := s.assignNewSession(w, r)
		return session, nil
	} else if err != nil {
		logger.Println("Can't find session. Reason:", err)
	}
	logger.Println("and session has been found:", session)
	return session, nil
}

func (s *SessionManager) assignNewSession(w http.ResponseWriter, r *http.Request) *Session {
	sid := s.sessionID()
	smlogger.Printf("Created new temp sessionID: %s", sid.String())
	sess := &Session{SessionID: sid, Lifetime: s.maxlifetime, OID: bson.NewObjectId(), Created: time.Now().Unix()}
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    sid.String(),
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(s.maxlifetime),
	}
	smlogger.Println("Assigning cookies to client")
	http.SetCookie(w, cookie)
	return sess
}

//SessionEnd removes session from browser and database
func (s *SessionManager) SessionEnd(w http.ResponseWriter, r *http.Request) {
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
	// Moved to daemon package
	// s.db.C(SESSIONCOLLECTION).Remove(bson.M{"session_id": cookie.Value})
}

//SessionGC removes all expired sessions
func (s *SessionManager) SessionGC() {
	t := time.Now()
	ch, _ := s.db.C(SESSIONCOLLECTION).RemoveAll(bson.M{
		"created": bson.M{
			"$lte": time.Now().Unix() - s.maxlifetime,
		},
	})
	ch1, _ := s.db.C(SESSIONCOLLECTION).RemoveAll(bson.M{
		"created": uuid.Nil.String(),
	})
	removed := ch.Removed + ch1.Removed
	smlogger.Printf("Expired session cleared (%03d). Took %s", removed, time.Since(t))
	time.AfterFunc(time.Minute*15, s.SessionGC)
}

//UpdateSession and save changes into db
func (s *SessionManager) UpdateSession(session *Session) error {
	smlogger.Printf("Updating session %s", session.OID.String())
	return session.Update(s.db)
}

//LoadSessionUUID from database by Session_ID
func (s *SessionManager) LoadSessionUUID(session *Session) error {
	smlogger.Printf("Loading session %s", session.SessionID.String())
	return session.ReadUUID(s.db)
}

//DeleteSession from database
func (s *SessionManager) DeleteSession(session *Session) error {
	smlogger.Printf("Deleting session %s", session.SessionID.String())
	return session.DeleteByID(s.db)
}

//LoadUser from database related to specified session
func (s *SessionManager) LoadUser(session *Session) (*User, error) {
	smlogger.Printf("Loading user (ID: %s) related to session %s", session.UserID, session.OID.String())
	return session.User(s.db)
}

//CreateSession and store it into database
func (s *SessionManager) CreateSession(session *Session) error {
	return session.Create(s.db)
}
