// Package validator enforces the password policy.
package validator

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// MaxPasswordBytes is the longest password bcrypt hashes in full; longer input is silently truncated.
const MaxPasswordBytes = 72

// Policy lists the rules a password must satisfy. Lengths count Unicode characters.
type Policy struct {
	MinLength      int
	MaxLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
	ForbidCommon   bool
}

// DefaultPolicy returns the policy applied by the service: 8 to 128 characters with upper and
// lower case letters, a digit and a special character, and not a well-known password.
func DefaultPolicy() Policy {
	return Policy{
		MinLength:      8,
		MaxLength:      128,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		ForbidCommon:   true,
	}
}

// ValidatePassword checks pw against p. It returns nil when the password is acceptable, otherwise
// an *apperror.AppError with code VALIDATION_ERROR whose Details["errors"] lists every violated rule.
func ValidatePassword(pw string, p Policy) error {
	violations := lengthViolations(pw, p)
	violations = append(violations, classViolations(pw, p)...)
	if p.ForbidCommon && isCommon(pw) {
		violations = append(violations, "password is too common")
	}
	if len(violations) == 0 {
		return nil
	}
	return apperror.ValidationError("password does not meet the policy", map[string]any{"errors": violations})
}

// lengthViolations checks the character limits of p and the bcrypt byte limit.
func lengthViolations(pw string, p Policy) []string {
	var out []string
	runes := utf8.RuneCountInString(pw)
	if runes < p.MinLength {
		out = append(out, fmt.Sprintf("password must be at least %d characters long", p.MinLength))
	}
	if p.MaxLength > 0 && runes > p.MaxLength {
		out = append(out, fmt.Sprintf("password must be at most %d characters long", p.MaxLength))
	}
	if len(pw) > MaxPasswordBytes {
		out = append(out, fmt.Sprintf("password must not exceed %d bytes in UTF-8; non-ASCII characters take several bytes each", MaxPasswordBytes))
	}
	return out
}

// classViolations checks the character classes required by p.
func classViolations(pw string, p Policy) []string {
	var upper, lower, digit, special bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			special = true
		}
	}

	var out []string
	if p.RequireUpper && !upper {
		out = append(out, "password must contain an uppercase letter")
	}
	if p.RequireLower && !lower {
		out = append(out, "password must contain a lowercase letter")
	}
	if p.RequireDigit && !digit {
		out = append(out, "password must contain a digit")
	}
	if p.RequireSpecial && !special {
		out = append(out, "password must contain a special character")
	}
	return out
}

// isCommon reports whether pw, compared case-insensitively, is a well-known password.
func isCommon(pw string) bool {
	_, ok := commonPasswords[strings.ToLower(pw)]
	return ok
}

// commonPasswords holds frequently leaked passwords in lower case.
var commonPasswords = map[string]struct{}{
	"password": {}, "password1": {}, "password123": {}, "password1!": {},
	"passw0rd": {}, "p@ssw0rd": {}, "p@ssword": {}, "pa$$w0rd": {},
	"123456": {}, "12345678": {}, "123456789": {}, "1234567890": {},
	"qwerty": {}, "qwerty123": {}, "qwertyuiop": {}, "qwerty1!": {},
	"letmein": {}, "welcome": {}, "welcome1": {}, "changeme": {},
	"admin": {}, "admin123": {}, "administrator": {}, "root": {}, "toor": {},
	"iloveyou": {}, "trustno1": {}, "sunshine": {}, "princess": {},
	"football": {}, "baseball": {}, "dragon": {}, "monkey": {}, "shadow": {},
	"superman": {}, "master": {}, "hello": {}, "abc123": {},
	"111111": {}, "000000": {}, "654321": {}, "987654321": {},
}
