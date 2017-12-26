//TODO: Add processing for os.Interrupt and syscall.SIGTERM
//TODO: Add parsable parameters from args
package main

import (
	"log"
	"math/rand"
	"os"
	"os/signal"
	"syscall"

	"github.com/ferux/mineme/daemon"
	"gopkg.in/mgo.v2"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const connString = "mongodb://localhost"

func main() {
	c := make(chan os.Signal, 3)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	db, err := mgo.Dial(connString)
	if err != nil {
		log.Fatal(err)
	}
	daemon.Run(":8888", db.DB("mineme"), true, os.Stdout, c)
	<-c

}

func randStringBytesRmndr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
