package domain

import "time"

// User is a registered account.
// PasswordTemporary marks a password that must be changed at the next login.
type User struct {
	ID                int64     `gorm:"primaryKey"`
	Email             string    `gorm:"uniqueIndex"`
	PasswordHash      string    `gorm:"not null"`
	PasswordTemporary bool      `gorm:"not null"`
	PasswordChangedAt time.Time `gorm:"not null"`
	FullName          string    `gorm:"not null"`
	IsBlocked         bool      `gorm:"not null"`
	CreatedAt         time.Time `gorm:"not null"`
	UpdatedAt         time.Time `gorm:"not null"`
}

// TableName returns the users table name.
func (User) TableName() string {
	return "users"
}

// PasswordExpired reports whether the password is older than maxAge at now.
// A non-positive maxAge disables expiry.
func (u *User) PasswordExpired(now time.Time, maxAge time.Duration) bool {
	return maxAge > 0 && now.Sub(u.PasswordChangedAt) > maxAge
}
