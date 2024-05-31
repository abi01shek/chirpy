package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// path and mutex for a data base
type DB struct {
	path  string
	mutex *sync.RWMutex
}

type Chirp struct {
	ID       int    `json:"id"`
	Body     string `json:"body"`
	Authorid int    `json:"author_id"`
}

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	EncPass     []byte `json:"encPass"`
	Rfrshtkn    string `json:"refresh_token"`
	Ischirpyred bool   `json:"is_chirpy_red"`
}

// maps ID to a chirp
type DBStructure struct {
	Chirps       map[int]Chirp  `json:"chirps"`
	Users        map[int]User   `json:"users"`
	EmailUIDHash map[string]int `json:"emailUIDHash"`
	RfrshUIDHash map[string]int `json:"rfrshUIDHash"`
}

// NewDB: creates a new database connection
// creates a database file if it doesnt exist
func NewDB(path string) (*DB, error) {
	myDB := DB{}
	myDB.path = path
	myDB.mutex = &sync.RWMutex{}

	// Locking creating the file and
	// initializing it
	myDB.mutex.Lock()
	defer myDB.mutex.Unlock()

	if _, err := os.Stat(myDB.path); os.IsNotExist(err) {
		// file does not exist
		// create an empty file
		dbHandle, err := os.Create(myDB.path)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Opened an empty database file: %s\n", myDB.path)
		dbHandle.Close()
	} else if err != nil {
		// file may or maynot exist
		return nil, err
	}

	return &myDB, nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	readData := DBStructure{}

	// lock the file for reading (no write will happen )
	db.mutex.RLock()
	contentBytes, err := os.ReadFile(db.path)
	if err != nil {
		return readData, err
	}
	db.mutex.RUnlock()

	// Unmarshall only if file is not empty
	// otherwise return emtpy struct
	if len(contentBytes) > 0 {
		err = json.Unmarshal(contentBytes, &readData)
		if err != nil {
			return DBStructure{}, err
		}
	}

	return readData, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	writeBytes, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	// lock file for writing and write
	// writefile truncates the file before writing, does not append to it
	db.mutex.Lock()
	defer db.mutex.Unlock()
	err = os.WriteFile(db.path, writeBytes, 0666)
	if err != nil {
		return err
	}

	return nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, authorid int) (Chirp, error) {
	// read the entire databse into main memory
	readData, err := db.loadDB()
	if err != nil {
		fmt.Printf("Error: %v", err)
		return Chirp{}, err
	}

	// create a new chirp
	writeChirp := Chirp{}
	writeChirp.Body = strings.TrimSpace(body)
	writeChirp.Authorid = authorid
	if len(readData.Chirps) == 0 {
		// database is emtpy start writing from ID 1
		readData.Chirps = make(map[int]Chirp)
		readData.Chirps[0] = Chirp{0, "", 0}
		writeChirp.ID = 1
	} else {
		// from all chirps, find the biggest ID
		max_id := 0
		for id := range readData.Chirps {
			if max_id < id {
				max_id = id
			}
		}
		writeChirp.ID = max_id + 1
	}

	// add the chirp into the database
	readData.Chirps[writeChirp.ID] = writeChirp

	// write the contents of entire memory into storage
	err = db.writeDB(readData)
	if err != nil {
		return Chirp{}, nil
	}

	return writeChirp, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	readData, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	keys := make([]int, len(readData.Chirps))
	for k := range readData.Chirps {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	chirps := make([]Chirp, len(readData.Chirps))
	for _, k := range keys {
		chirps[k] = readData.Chirps[k]
	}

	return chirps, nil
}

// CreateUser: creates a new user and saves it to disk
func (db *DB) CreateUser(email string, passw string) (User, error) {
	// read the entire databse into main memory
	readData, err := db.loadDB()
	if err != nil {
		fmt.Printf("Error: %v", err)
		return User{}, err
	}

	// create a new user and encrypt user password
	writeData := User{}
	writeData.Email = strings.TrimSpace(email)
	encPass, err := bcrypt.GenerateFromPassword([]byte(passw), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	writeData.EncPass = encPass
	writeData.Ischirpyred = false

	if userID, exists := readData.EmailUIDHash[writeData.Email]; exists {
		writeData.ID = userID
	} else {
		if len(readData.Users) == 0 {
			// database is emtpy start writing from ID 1
			readData.Users = make(map[int]User)
			readData.Users[0] = User{0, "", nil, "", false}
			writeData.ID = 1
		} else {
			// from all users, find the biggest ID
			max_id := 0
			for id := range readData.Users {
				if max_id < id {
					max_id = id
				}
			}
			writeData.ID = max_id + 1
		}

		if len(readData.EmailUIDHash) == 0 {
			readData.EmailUIDHash = make(map[string]int)
		}
		readData.EmailUIDHash[writeData.Email] = writeData.ID
	}

	// add the user into the database in main memory
	readData.Users[writeData.ID] = writeData
	// write the contents of entire memory into storage
	err = db.writeDB(readData)
	if err != nil {
		return User{}, nil
	}

	return writeData, nil
}

// GetUsers: returns all users in the database
func (db *DB) GetUsers() ([]User, error) {
	readData, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	users := make([]User, len(readData.Users))
	userIdx := 0
	for _, user := range readData.Users {
		users[userIdx] = user
		userIdx++
	}

	return users, nil
}

func (db *DB) CheckPass(email string, passw string) (User, error) {
	email = strings.TrimSpace(email)

	// read all users from database
	readData, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	// check if user is in database
	if userID, exists := readData.EmailUIDHash[email]; exists {
		user := readData.Users[userID]
		// Comparing the password with the hash
		err = bcrypt.CompareHashAndPassword(user.EncPass, []byte(passw))
		if err != nil {
			return User{}, err
		}
		return user, nil
	} else {
		err = errors.New("user does not exist")
		return User{}, err
	}

}

// UpdateUserEmailPass: read the database and update the user's email
// and password
func (db *DB) UpdateUserEmailPass(userid int, email string, passw string) (User, error) {
	readData, err := db.loadDB()
	if err != nil {
		fmt.Printf("Error: %v", err)
		return User{}, err
	}

	encPass, err := bcrypt.GenerateFromPassword([]byte(passw), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	prevemail := ""
	if user, ok := readData.Users[userid]; ok {
		prevemail = user.Email
		user.Email = strings.TrimSpace(email)
		user.EncPass = encPass
		readData.Users[userid] = user
		delete(readData.EmailUIDHash, prevemail)
		readData.EmailUIDHash[user.Email] = userid
	} else {
		return User{}, errors.New("cannot find user with given user id")
	}

	// write the contents of entire memory into storage
	err = db.writeDB(readData)
	if err != nil {
		return User{}, nil
	}

	return readData.Users[userid], nil
}

func (db *DB) UpdateUserChirpyRed(userid int) (User, error) {
	// read entire database to memory
	readData, err := db.loadDB()
	if err != nil {
		fmt.Println(err)
		return User{}, err
	}

	if user, ok := readData.Users[userid]; ok {
		user.Ischirpyred = true
		readData.Users[userid] = user
	} else {
		return User{}, errors.New("cannot find user with given user id")
	}
	// write the contents of entire memory into storage
	err = db.writeDB(readData)
	if err != nil {
		return User{}, nil
	}

	return readData.Users[userid], nil
}

// UpdateUserRefreshToken: store new value of refresh token in database for user
func (db *DB) UpdateUserRfrshTkn(userid int, rfrshtkn string) (User, error) {
	// read entire database into memory
	readData, err := db.loadDB()
	if err != nil {
		fmt.Printf("Error: %v", err)
		return User{}, err
	}

	if len(readData.RfrshUIDHash) == 0 {
		readData.RfrshUIDHash = make(map[string]int)
	}
	if user, ok := readData.Users[userid]; ok {
		user.Rfrshtkn = rfrshtkn
		readData.RfrshUIDHash[rfrshtkn] = userid
	} else {
		return User{}, errors.New("cannot find user with given user id")
	}

	// write the contents of entire memory into storage
	err = db.writeDB(readData)
	if err != nil {
		return User{}, nil
	}

	return readData.Users[userid], nil
}

func (db *DB) CheckRfrshTkn(inrfrshtkn string) (User, error) {
	// read entire database into memory
	readData, err := db.loadDB()
	if err != nil {
		fmt.Printf("Error: %v", err)
		return User{}, err
	}

	// check if refresh token is present in database
	if userid, ok := readData.RfrshUIDHash[inrfrshtkn]; ok {
		if _, ok := readData.Users[userid]; ok {
			return readData.Users[userid], nil
		} else {
			return User{}, errors.New("cannot find user for given user id")
		}
	} else {
		return User{}, errors.New("invalid refresh token")
	}
}

// RevokeRfrshToken: remove the refresh token stored
func (db *DB) RevokeRfrshTkn(inrfrshtkn string) error {
	// read entire database into memory
	readData, err := db.loadDB()
	if err != nil {
		fmt.Printf("Error: %v", err)
		return err
	}

	delete(readData.RfrshUIDHash, inrfrshtkn)

	// write the contents of entire memory into storage
	err = db.writeDB(readData)
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) DeleteChirp(chirpid int) error {
	// dummy not really deleting anything
	return nil
}
