// Package validator provides custom validation functions and utilities.
// Пакет validator предоставляет кастомные функции валидации и утилиты.
package validator

import (
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var (
	// emailDomainRegex validates email domain format.
	emailDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// CustomValidator wraps the standard validator with custom validations.
type CustomValidator struct {
	validate *validator.Validate
}

// New creates a new CustomValidator with all custom validations registered.
func New() (*CustomValidator, error) {
	v := validator.New()

	// Register custom validations
	if err := v.RegisterValidation("strongpassword", validateStrongPassword); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("safeemail", validateSafeEmail); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("alphanumspace", validateAlphanumericWithSpaces); err != nil {
		return nil, err
	}

	if err := v.RegisterValidation("nohtml", validateNoHTML); err != nil {
		return nil, err
	}

	return &CustomValidator{validate: v}, nil
}

// Validate validates a struct using the registered validations.
func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validate.Struct(i)
}

// validateStrongPassword ensures password meets complexity requirements.
// Requirements: 8+ chars, uppercase, lowercase, digit, special character.
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// validateSafeEmail validates email format and checks for common attack patterns.
func validateSafeEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()

	// Basic format check
	if !emailDomainRegex.MatchString(email) {
		return false
	}

	// Check for common injection patterns
	dangerousPatterns := []string{
		"<script",
		"javascript:",
		"data:",
		"\n",
		"\r",
		"%0a",
		"%0d",
	}

	emailLower := strings.ToLower(email)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(emailLower, pattern) {
			return false
		}
	}

	return true
}

// validateAlphanumericWithSpaces allows only alphanumeric characters and spaces.
func validateAlphanumericWithSpaces(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	for _, char := range value {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !unicode.IsSpace(char) {
			return false
		}
	}

	return true
}

// validateNoHTML ensures the field contains no HTML tags.
func validateNoHTML(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	return !htmlTagPattern.MatchString(value)
}

// ValidationErrors represents a map of field names to error messages.
type ValidationErrors map[string]string

// FormatValidationErrors converts validator.ValidationErrors to a user-friendly format.
// FormatValidationErrors преобразует validator.ValidationErrors в удобный для пользователя формат.
func FormatValidationErrors(err error) ValidationErrors {
	result := make(ValidationErrors)

	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		for _, e := range validationErrors {
			field := strings.ToLower(e.Field())
			result[field] = formatErrorMessage(e)
		}
	}

	return result
}

// formatErrorMessage returns a user-friendly error message for a validation error.
func formatErrorMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Must be a valid email address"
	case "min":
		return "Must be at least " + e.Param() + " characters"
	case "max":
		return "Must be at most " + e.Param() + " characters"
	case "strongpassword":
		return "Must be at least 8 characters with uppercase, lowercase, digit, and special character"
	case "safeemail":
		return "Invalid email format"
	case "alphanumspace":
		return "Must contain only letters, numbers, and spaces"
	case "nohtml":
		return "HTML tags are not allowed"
	case "oneof":
		return "Must be one of: " + e.Param()
	default:
		return "Invalid value"
	}
}

// PasswordStrength represents the strength of a password.
// PasswordStrength представляет силу пароля.
type PasswordStrength int

// Password strength levels.
// Уровни силы пароля.
const (
	PasswordWeak   PasswordStrength = iota // Weak password / Слабый пароль
	PasswordFair                           // Fair password / Средний пароль
	PasswordGood                           // Good password / Хороший пароль
	PasswordStrong                         // Strong password / Сильный пароль
)

// CheckPasswordStrength evaluates the strength of a password.
func CheckPasswordStrength(password string) PasswordStrength {
	score := calculateLengthScore(len(password)) + calculateCharVarietyScore(password)
	return scoreToStrength(score)
}

// calculateLengthScore returns score based on password length.
func calculateLengthScore(length int) int {
	score := 0
	for _, threshold := range []int{8, 12, 16} {
		if length >= threshold {
			score++
		}
	}
	return score
}

// calculateCharVarietyScore returns score based on character variety.
func calculateCharVarietyScore(password string) int {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return boolToInt(hasUpper) + boolToInt(hasLower) + boolToInt(hasDigit) + boolToInt(hasSpecial)
}

// boolToInt converts boolean to integer (1 for true, 0 for false).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// scoreToStrength converts numeric score to PasswordStrength.
func scoreToStrength(score int) PasswordStrength {
	switch {
	case score >= 6:
		return PasswordStrong
	case score >= 4:
		return PasswordGood
	case score >= 2:
		return PasswordFair
	default:
		return PasswordWeak
	}
}

// String returns a string representation of password strength.
func (ps PasswordStrength) String() string {
	switch ps {
	case PasswordStrong:
		return "strong"
	case PasswordGood:
		return "good"
	case PasswordFair:
		return "fair"
	case PasswordWeak:
		return "weak"
	default:
		return "weak"
	}
}

// PasswordRequirements defines configurable password complexity requirements.
// PasswordRequirements определяет конфигурируемые требования к сложности пароля.
type PasswordRequirements struct {
	MinLength        int  // Minimum password length / Минимальная длина пароля
	MaxLength        int  // Maximum password length / Максимальная длина пароля
	RequireUppercase bool // Require at least one uppercase letter / Требовать хотя бы одну заглавную букву
	RequireLowercase bool // Require at least one lowercase letter / Требовать хотя бы одну строчную букву
	RequireDigit     bool // Require at least one digit / Требовать хотя бы одну цифру
	RequireSpecial   bool // Require at least one special character / Требовать хотя бы один спецсимвол
	DisallowCommon   bool // Disallow common passwords / Запретить распространённые пароли
	DisallowSequence bool // Disallow sequential characters / Запретить последовательности символов
}

// DefaultPasswordRequirements returns the default password requirements.
// DefaultPasswordRequirements возвращает требования к паролю по умолчанию.
func DefaultPasswordRequirements() PasswordRequirements {
	return PasswordRequirements{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
		DisallowCommon:   true,
		DisallowSequence: true,
	}
}

// PasswordValidationResult contains the result of password validation.
// PasswordValidationResult содержит результат валидации пароля.
type PasswordValidationResult struct {
	Valid    bool     // Whether the password is valid / Валиден ли пароль
	Errors   []string // List of validation errors / Список ошибок валидации
	Strength PasswordStrength
}

// charTypeAnalysis holds the result of character type analysis.
type charTypeAnalysis struct {
	hasUpper   bool
	hasLower   bool
	hasDigit   bool
	hasSpecial bool
}

// analyzeCharTypes analyzes character types in a password.
func analyzeCharTypes(password string) charTypeAnalysis {
	var result charTypeAnalysis
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			result.hasUpper = true
		case unicode.IsLower(char):
			result.hasLower = true
		case unicode.IsDigit(char):
			result.hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			result.hasSpecial = true
		}
	}
	return result
}

// validateLength checks password length requirements.
func validateLength(password string, req PasswordRequirements) []string {
	var errors []string
	if len(password) < req.MinLength {
		errors = append(errors, "Password must be at least "+itoa(req.MinLength)+" characters long")
	}
	if req.MaxLength > 0 && len(password) > req.MaxLength {
		errors = append(errors, "Password must be at most "+itoa(req.MaxLength)+" characters long")
	}
	return errors
}

// validateCharTypes checks required character types.
func validateCharTypes(analysis charTypeAnalysis, req PasswordRequirements) []string {
	var errors []string
	if req.RequireUppercase && !analysis.hasUpper {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}
	if req.RequireLowercase && !analysis.hasLower {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}
	if req.RequireDigit && !analysis.hasDigit {
		errors = append(errors, "Password must contain at least one digit")
	}
	if req.RequireSpecial && !analysis.hasSpecial {
		errors = append(errors, "Password must contain at least one special character (!@#$%^&*...)")
	}
	return errors
}

// validatePatterns checks for common passwords and bad patterns.
func validatePatterns(password string, req PasswordRequirements) []string {
	var errors []string
	if req.DisallowCommon && isCommonPassword(password) {
		errors = append(errors, "Password is too common, please choose a more unique password")
	}
	if req.DisallowSequence && hasSequentialChars(password, 4) {
		errors = append(errors, "Password contains sequential characters (e.g., 1234, abcd)")
	}
	if hasRepeatedChars(password, 4) {
		errors = append(errors, "Password contains too many repeated characters")
	}
	return errors
}

// ValidatePassword validates a password against the given requirements.
// ValidatePassword проверяет пароль на соответствие заданным требованиям.
func ValidatePassword(password string, req PasswordRequirements) PasswordValidationResult {
	result := PasswordValidationResult{
		Valid:    true,
		Errors:   []string{},
		Strength: CheckPasswordStrength(password),
	}

	// Validate length
	result.Errors = append(result.Errors, validateLength(password, req)...)

	// Validate character types
	analysis := analyzeCharTypes(password)
	result.Errors = append(result.Errors, validateCharTypes(analysis, req)...)

	// Validate patterns
	result.Errors = append(result.Errors, validatePatterns(password, req)...)

	// Set valid to false if there are any errors
	result.Valid = len(result.Errors) == 0

	return result
}

// ValidatePasswordDefault validates password with default requirements.
// ValidatePasswordDefault проверяет пароль с требованиями по умолчанию.
func ValidatePasswordDefault(password string) PasswordValidationResult {
	return ValidatePassword(password, DefaultPasswordRequirements())
}

// isCommonPassword checks if password is in the list of common passwords.
// isCommonPassword проверяет, является ли пароль распространённым.
func isCommonPassword(password string) bool {
	commonPasswords := map[string]bool{
		"password":    true,
		"password1":   true,
		"password123": true,
		"123456":      true,
		"12345678":    true,
		"123456789":   true,
		"1234567890":  true,
		"qwerty":      true,
		"qwerty123":   true,
		"qwertyuiop":  true,
		"letmein":     true,
		"welcome":     true,
		"admin":       true,
		"admin123":    true,
		"root":        true,
		"toor":        true,
		"pass":        true,
		"test":        true,
		"guest":       true,
		"master":      true,
		"changeme":    true,
		"hello":       true,
		"dragon":      true,
		"baseball":    true,
		"iloveyou":    true,
		"trustno1":    true,
		"sunshine":    true,
		"princess":    true,
		"football":    true,
		"shadow":      true,
		"superman":    true,
		"michael":     true,
		"ninja":       true,
		"mustang":     true,
		"password1!":  true,
		"abc123":      true,
		"111111":      true,
		"000000":      true,
		"654321":      true,
		"987654321":   true,
		"passw0rd":    true,
		"p@ssw0rd":    true,
		"p@ssword":    true,
	}

	return commonPasswords[strings.ToLower(password)]
}

// hasSequentialChars checks if password contains sequential characters.
// hasSequentialChars проверяет, содержит ли пароль последовательности символов.
func hasSequentialChars(password string, minSeqLength int) bool {
	if len(password) < minSeqLength {
		return false
	}

	runes := []rune(strings.ToLower(password))

	// Check for ascending sequences / Проверка восходящих последовательностей
	ascCount := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]+1 {
			ascCount++
			if ascCount >= minSeqLength {
				return true
			}
		} else {
			ascCount = 1
		}
	}

	// Check for descending sequences / Проверка нисходящих последовательностей
	descCount := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]-1 {
			descCount++
			if descCount >= minSeqLength {
				return true
			}
		} else {
			descCount = 1
		}
	}

	// Check for keyboard sequences / Проверка клавиатурных последовательностей
	keyboardSequences := []string{
		"qwerty", "asdfgh", "zxcvbn", "qazwsx", "!@#$%^",
		"йцукен", "фывапр", "ячсмит",
	}

	passwordLower := strings.ToLower(password)
	for _, seq := range keyboardSequences {
		if len(seq) >= minSeqLength && strings.Contains(passwordLower, seq[:minSeqLength]) {
			return true
		}
	}

	return false
}

// hasRepeatedChars checks if password contains too many repeated characters.
// hasRepeatedChars проверяет, содержит ли пароль слишком много повторяющихся символов.
func hasRepeatedChars(password string, maxRepeats int) bool {
	if len(password) < maxRepeats {
		return false
	}

	runes := []rune(password)
	repeatCount := 1

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			repeatCount++
			if repeatCount >= maxRepeats {
				return true
			}
		} else {
			repeatCount = 1
		}
	}

	return false
}

// itoa converts int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
