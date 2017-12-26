//TODO: Add ability to modify user's data
//TODO: Add profile page
package daemon

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/gorilla/mux"

	"github.com/ferux/mineme/mineme"

	"gopkg.in/mgo.v2"
)

var logger *log.Logger
var sManager *mineme.SessionManager
var model *mineme.Model

//Run http backend server
func Run(laddr string, db *mgo.Database, debug bool, debugW io.Writer, notify <-chan os.Signal) (chan error, chan interface{}) {
	donec := make(chan interface{}, 1)
	errc := make(chan error, 0)
	go func() {
		if debug {
			logger = log.New(debugW, "[Daemon] ", log.Ldate+log.Ltime)
		} else {
			logger = log.New(ioutil.Discard, "", 0)
		}
		logger.Println("DB available:", db.Session.Ping() == nil)
		errc <- run(laddr, db, notify, debug, debugW)
		donec <- nil
	}()

	return errc, donec
}

func run(laddr string, db *mgo.Database, notify <-chan os.Signal, debug bool, debugW io.Writer) error {
	if db == nil {
		return mineme.ErrDBIsNil
	}
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return err
	}
	sManager, _ = mineme.NewSessionManager(db, debug, debugW)
	model, _ = mineme.NewModel(db, debug, debugW)
	router := makeRoutes()
	motd := "* Begin listening for new requests *"
	logger.Println(strings.Repeat("*", len(motd)))
	logger.Println(motd)
	logger.Println(fmt.Sprintf("%s%s", strings.Repeat("*", len(motd)), strings.Repeat("\n", 2)))
	return http.Serve(l, router)
}

func makeRoutes() http.Handler {
	router := mux.NewRouter()
	hostname, _ := os.Hostname()
	router = router.Host(hostname).Subrouter().Headers("Content-Type", "application/json").Subrouter()
	router.Handle("/", http.FileServer(http.Dir("./assets/")))
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.Handle("/logout", authreq{logoutHandler}).Methods("POST")
	router.HandleFunc("/register", registerNewUserHandler).Methods("POST")
	return router
}

//ServerResponse back to client
type ServerResponse struct {
	Result  string                  `json:"result,omitempty"`
	Details *DetailResponse         `json:"details,omitempty"`
	Session *mineme.Session         `json:"session,omitempty"`
	User    *mineme.SafeUserDetails `json:"user,omitempty"`
}

//ClientRequest from client
type ClientRequest struct {
	Result string `json:"result,omitempty"`
	User   *struct {
		Login       string `json:"login,omitempty"`
		FirstName   string `json:"first_name,omitempty"`
		LastName    string `json:"last_name,omitempty"`
		Password    string `json:"password,omitempty"`
		Description string `json:"description,omitempty"`
		Age         int    `json:"age,omitempty"`
	} `json:"user,omitempty"`
}

//DetailResponse for errors
type DetailResponse struct {
	Code      code   `json:"code,omitempty"`
	Text      string `json:"text,omitempty"`
	Status    bool   `json:"status,omitempty"`
	ReponseID string `json:"error_id,omitempty"`
}

type code int

//StatusCodes for errors
const (
	OKAY code = 1000 + iota
	LOGINNOTFOUND
	LOGINREQUIRED
	NOTLOGGEDIN
	ALREADYLOGGEDIN
	LOGINTAKEN
	UNKNOWNERROR
)

//FillErrorResponse unifies responses
func FillErrorResponse(c code) *ServerResponse {
	switch c {
	case LOGINREQUIRED:
		return &ServerResponse{
			Result: "error",
			Details: &DetailResponse{
				Code:      c,
				Text:      "You need to be logged in to proceed this action",
				Status:    false,
				ReponseID: uuid.New().String(),
			},
		}
	case NOTLOGGEDIN:
		return &ServerResponse{
			Result: "error",
			Details: &DetailResponse{
				Code:      c,
				Text:      "You are not logged in",
				Status:    false,
				ReponseID: uuid.New().String(),
			},
		}
	case http.StatusBadRequest:
		return &ServerResponse{
			Result: "error",
			Details: &DetailResponse{
				Code:      c,
				Text:      "Something went wrong and ended with an error. Sorry.",
				Status:    false,
				ReponseID: uuid.New().String(),
			},
		}
	case ALREADYLOGGEDIN:
		return &ServerResponse{
			Result: "error",
			Details: &DetailResponse{
				Code:      c,
				Text:      "You are already logged in",
				Status:    false,
				ReponseID: uuid.New().String(),
			},
		}
	case LOGINTAKEN:
		return &ServerResponse{
			Result: "error",
			Details: &DetailResponse{
				Code:      c,
				Text:      "Login already taken",
				Status:    false,
				ReponseID: uuid.New().String(),
			},
		}
	default:
		return &ServerResponse{
			Result: "error",
			Details: &DetailResponse{
				Code:      c,
				Text:      "Unknown Error",
				Status:    false,
				ReponseID: uuid.New().String(),
			},
		}
	}

}

func fillGoodResponse(c code) *ServerResponse {
	switch c {
	case OKAY:
		return &ServerResponse{
			Result: "ok",
			Details: &DetailResponse{
				Code:   c,
				Text:   "Success",
				Status: true,
			},
		}
	default:
		return &ServerResponse{
			Result: "ok",
			Details: &DetailResponse{
				Code:   c,
				Text:   "Success",
				Status: true,
			},
		}
	}
}

type authreq struct {
	next http.HandlerFunc
}

func (a authreq) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, _ := sManager.SessionStart(w, r)
	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	u, _ := sManager.LoadUser(session)
	if session.UserID == uuid.Nil {
		logger.Printf("User authorization required to perform this action: %s", r.RequestURI)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINREQUIRED))
		return
	}
	if !model.CheckUserExists("", "", u) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
		return
	}
	model.ReadUUID(u)
	if u.Status == mineme.USERPERMAMENTLY {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusForbidden))
		return
	}
	logger.Println(u)
	ctx := context.WithValue(r.Context(), mineme.SessionContext("sessionid"), session.SessionID.String())
	r = r.WithContext(ctx)
	logger.Println("sessionid attached to request context")
	session.Created = time.Now().Unix()
	logger.Println("Session time has been updated")
	a.next.ServeHTTP(w, r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sManager.SessionStart(w, r)
	if session == nil {
		logger.Println("Session is nil. That is STRANGE!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	if session.UserID != uuid.Nil {
		logger.Printf("Session.UserID is not empty [%v]", session.UserID)
		u := &mineme.User{ID: session.UserID}
		if !model.CheckUserExists("", "", u) {
			logger.Println("but this user doesn't exist")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
			return
		}
		logger.Println("and the user exists")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(FillErrorResponse(ALREADYLOGGEDIN))
		return
	}
	logger.Printf("Temp session doesn't have any bounded user. Authorizing.")
	if ctype := r.Header.Get("Content-Type"); ctype != "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}

	var resp *ClientRequest
	err := json.NewDecoder(r.Body).Decode(&resp)
	r.Body.Close()
	if err != nil || resp == nil || resp.User == nil {
		logger.Printf("Got an error trying to proceed user login: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	logger.Printf("Found credentials for user %s", resp.User.Login)
	if !model.CheckUserExists(resp.User.Login, resp.User.Password, nil) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
		return
	}
	encryptedPassword := md5.Sum([]byte(resp.User.Password))
	u := &mineme.User{Login: resp.User.Login, Password: encryptedPassword}
	err = model.AuthUser(u)
	if err != nil {
		logger.Printf("Can't authenticate user. Reason: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
		return
	}
	logger.Println("User authenticated. Attaching session to this user")
	session.UserID = u.ID
	//I think it is a bad idea to assign new _id for the second time
	// if session.OID == "" {
	// 	session.OID = bson.NewObjectId()
	// }
	if session.OID == "" {
		logger.Println("Session OID is empty somehow...")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	err = sManager.CreateSession(session)
	if err != nil {
		logger.Println("There was an error creating session", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	logger.Printf("Session %s has been stored to the database", session.OID)
	respQuery := fillGoodResponse(OKAY)
	//TODO: Need to make API requests to Coinhive for user statistics retrieve.
	respQuery.User = u.MakeSafeUser()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(respQuery)
}

func registerNewUserHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sManager.SessionStart(w, r)
	req := &ClientRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil || req.User == nil {
		seresp := FillErrorResponse(http.StatusBadRequest)
		seresp.Details.Text = "Bad Request"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(&seresp)
		return
	}

	userNew, err := model.CreateNewUser(req.User.Login, req.User.Password, req.User.FirstName, req.User.LastName, req.User.Age)
	if err != nil || userNew == nil {
		logger.Printf("Got an error trying to proceed user register: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	logger.Printf("Created new user: %v", userNew)
	session.UserID = userNew.ID
	sManager.UpdateSession(session)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(fillGoodResponse(OKAY))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(mineme.SessionContext("sessionid")).(string)
	if session == "" || !ok {
		logger.Println("Can't retrieve session from context")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(FillErrorResponse(NOTLOGGEDIN))
		return
	}
	sid, err := uuid.Parse(session)
	if err != nil {
		logger.Println("Can't parse sessionid:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
	}
	s := &mineme.Session{SessionID: sid}
	logger.Println("Deleting session from database")
	err = sManager.DeleteSession(s)
	if err != nil {
		logger.Println("Can't delete session. Reason: ", err)
	}
	sManager.SessionEnd(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(fillGoodResponse(OKAY))
}
