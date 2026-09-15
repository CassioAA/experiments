package model

import "time"

type User struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	Activate  bool      `json:"activate"` // if suspending or pending verification
	CreatedAt time.Time `json:"created_at"`
}
