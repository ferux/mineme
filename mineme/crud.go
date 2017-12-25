package mineme

import "gopkg.in/mgo.v2"

//CRUD interface
type CRUD interface {
	Create(*mgo.Database) error
	Read(*mgo.Database) error
	Update(*mgo.Database) error
	Delete(*mgo.Database) error
}
