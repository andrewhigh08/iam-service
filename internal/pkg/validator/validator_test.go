package validator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	v, err := New()
	require.NoError(t, err)
	assert.NotNil(t, v)
}

func TestCustomValidator_Validate(t *testing.T) {
	v, err := New()
	require.NoError(t, err)

	type testStruct struct {
		Email    string `validate:"required,safeemail"`
		Password string `validate:"required,strongpassword"`
		Name     string `validate:"required,alphanumspace"`
		Bio      string `validate:"nohtml"`
	}

	tests := []struct {
		name    string
		input   testStruct
		wantErr bool
	}{
		{
			name: "valid input",
			input: testStruct{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     "John Doe",
				Bio:      "Software developer",
			},
			wantErr: false,
		},
		{
			name: "invalid email",
			input: testStruct{
				Email:    "invalid-email",
				Password: "SecurePass123!",
				Name:     "John Doe",
				Bio:      "Software developer",
			},
			wantErr: true,
		},
		{
			name: "weak password",
			input: testStruct{
				Email:    "test@example.com",
				Password: "weak",
				Name:     "John Doe",
				Bio:      "Software developer",
			},
			wantErr: true,
		},
		{
			name: "name with special chars",
			input: testStruct{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     "John@Doe!",
				Bio:      "Software developer",
			},
			wantErr: true,
		},
		{
			name: "bio with HTML",
			input: testStruct{
				Email:    "test@example.com",
				Password: "SecurePass123!",
				Name:     "John Doe",
				Bio:      "<script>alert('xss')</script>",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateStrongPassword(t *testing.T) {
	v, err := New()
	require.NoError(t, err)

	type passwordStruct struct {
		Password string `validate:"strongpassword"`
	}

	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{"valid password", "SecurePass123!", true},
		{"valid with symbols", "Test@123$Password", true},
		{"too short", "Aa1!", false},
		{"no uppercase", "securepass123!", false},
		{"no lowercase", "SECUREPASS123!", false},
		{"no digit", "SecurePassword!", false},
		{"no special char", "SecurePass12345", false},
		{"empty", "", false},
		{"only letters", "SecurePassword", false},
		{"unicode special chars", "Пароль123!", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(passwordStruct{Password: tt.password})
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateSafeEmail(t *testing.T) {
	v, err := New()
	require.NoError(t, err)

	type emailStruct struct {
		Email string `validate:"safeemail"`
	}

	tests := []struct {
		name  string
		email string
		valid bool
	}{
		{"valid email", "user@example.com", true},
		{"valid with subdomain", "user@mail.example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "user.name@example.com", true},
		{"invalid format", "invalid-email", false},
		{"missing domain", "user@", false},
		{"missing at", "userexample.com", false},
		{"script injection", "user<script>@example.com", false},
		{"javascript injection", "javascript:alert@example.com", false},
		{"newline injection", "user\n@example.com", false},
		{"carriage return", "user\r@example.com", false},
		{"encoded newline", "user%0a@example.com", false},
		{"encoded CR", "user%0d@example.com", false},
		{"data URI", "data:text@example.com", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(emailStruct{Email: tt.email})
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateAlphanumericWithSpaces(t *testing.T) {
	v, err := New()
	require.NoError(t, err)

	type nameStruct struct {
		Name string `validate:"alphanumspace"`
	}

	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"letters only", "JohnDoe", true},
		{"with spaces", "John Doe", true},
		{"with numbers", "John Doe 123", true},
		{"unicode letters", "Иван Иванов", true},
		{"with special chars", "John@Doe", false},
		{"with punctuation", "John, Doe!", false},
		{"with dash", "John-Doe", false},
		{"empty", "", true},
		{"only spaces", "   ", true},
		{"numbers only", "12345", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(nameStruct{Name: tt.value})
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateNoHTML(t *testing.T) {
	v, err := New()
	require.NoError(t, err)

	type bioStruct struct {
		Bio string `validate:"nohtml"`
	}

	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"plain text", "Hello, World!", true},
		{"with numbers", "User 123", true},
		{"empty", "", true},
		{"script tag", "<script>alert('xss')</script>", false},
		{"div tag", "<div>content</div>", false},
		{"img tag", "<img src='x'>", false},
		{"self-closing tag", "<br/>", false},
		{"malformed tag", "<div", true},           // no closing >, so regex doesn't match
		{"angle brackets in text", "5 > 3", true}, // single > is not a tag
		{"html entities", "&lt;script&gt;", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(bioStruct{Bio: tt.value})
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFormatValidationErrors(t *testing.T) {
	v, err := New()
	require.NoError(t, err)

	type testStruct struct {
		Email    string `validate:"required,email"`
		Password string `validate:"required,min=8"`
		Name     string `validate:"required"`
	}

	tests := []struct {
		name           string
		input          testStruct
		expectedFields []string
	}{
		{
			name:           "missing required fields",
			input:          testStruct{},
			expectedFields: []string{"email", "password", "name"},
		},
		{
			name: "invalid email format",
			input: testStruct{
				Email:    "invalid",
				Password: "12345678",
				Name:     "John",
			},
			expectedFields: []string{"email"},
		},
		{
			name: "password too short",
			input: testStruct{
				Email:    "test@example.com",
				Password: "short",
				Name:     "John",
			},
			expectedFields: []string{"password"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			require.Error(t, err)

			formatted := FormatValidationErrors(err)
			assert.Len(t, formatted, len(tt.expectedFields))

			for _, field := range tt.expectedFields {
				assert.Contains(t, formatted, field)
				assert.NotEmpty(t, formatted[field])
			}
		})
	}
}

func TestFormatValidationErrors_NonValidationError(t *testing.T) {
	result := FormatValidationErrors(assert.AnError)
	assert.Empty(t, result)
}

func TestCheckPasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected PasswordStrength
	}{
		{"empty password", "", PasswordWeak},
		{"short simple", "abc", PasswordWeak},
		{"medium length lowercase", "abcdefgh", PasswordFair},
		{"with upper and lower", "Abcdefgh", PasswordFair},
		{"with digits", "Abcdef12", PasswordGood},
		{"all char types short", "Abc123!@", PasswordGood},
		{"all char types medium", "Abcdef123!@#", PasswordStrong},
		{"all char types long", "AbcdefghIJKL123!@#$", PasswordStrong},
		{"very long simple", "abcdefghijklmnop", PasswordGood}, // length=16 (score 3) + lowercase (score 1) = 4
		{"unicode password", "Пароль123!Привет", PasswordStrong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckPasswordStrength(tt.password)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPasswordStrength_String(t *testing.T) {
	tests := []struct {
		strength PasswordStrength
		expected string
	}{
		{PasswordWeak, "weak"},
		{PasswordFair, "fair"},
		{PasswordGood, "good"},
		{PasswordStrong, "strong"},
		{PasswordStrength(999), "weak"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.strength.String())
		})
	}
}

func TestCalculateLengthScore(t *testing.T) {
	tests := []struct {
		length   int
		expected int
	}{
		{0, 0},
		{7, 0},
		{8, 1},
		{11, 1},
		{12, 2},
		{15, 2},
		{16, 3},
		{20, 3},
	}

	for _, tt := range tests {
		result := calculateLengthScore(tt.length)
		assert.Equal(t, tt.expected, result, "length=%d", tt.length)
	}
}

func TestCalculateCharVarietyScore(t *testing.T) {
	tests := []struct {
		password string
		expected int
	}{
		{"", 0},
		{"abc", 1},
		{"ABC", 1},
		{"123", 1},
		{"!@#", 1},
		{"aA", 2},
		{"aA1", 3},
		{"aA1!", 4},
	}

	for _, tt := range tests {
		result := calculateCharVarietyScore(tt.password)
		assert.Equal(t, tt.expected, result, "password=%q", tt.password)
	}
}

func TestBoolToInt(t *testing.T) {
	assert.Equal(t, 1, boolToInt(true))
	assert.Equal(t, 0, boolToInt(false))
}

func TestValidatePassword(t *testing.T) {
	req := DefaultPasswordRequirements()

	tests := []struct {
		name          string
		password      string
		expectValid   bool
		expectErrors  int
		errorContains string
	}{
		{
			name:        "valid strong password",
			password:    "SecurePass123!",
			expectValid: true,
		},
		{
			name:          "too short",
			password:      "Abc1!",
			expectValid:   false,
			errorContains: "at least 8 characters",
		},
		{
			name:          "missing uppercase",
			password:      "securepass123!",
			expectValid:   false,
			errorContains: "uppercase letter",
		},
		{
			name:          "missing lowercase",
			password:      "SECUREPASS123!",
			expectValid:   false,
			errorContains: "lowercase letter",
		},
		{
			name:          "missing digit",
			password:      "SecurePassword!",
			expectValid:   false,
			errorContains: "digit",
		},
		{
			name:          "missing special character",
			password:      "SecurePass123",
			expectValid:   false,
			errorContains: "special character",
		},
		{
			name:          "common password",
			password:      "P@ssw0rd",
			expectValid:   false,
			errorContains: "too common",
		},
		{
			name:          "sequential characters",
			password:      "Abcd1234!@#",
			expectValid:   false,
			errorContains: "sequential",
		},
		{
			name:          "repeated characters",
			password:      "Seeeeecure1!",
			expectValid:   false,
			errorContains: "repeated",
		},
		{
			name:        "valid with unicode",
			password:    "Пароль123!Ab",
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePassword(tt.password, req)
			assert.Equal(t, tt.expectValid, result.Valid, "password=%q", tt.password)

			if !tt.expectValid && tt.errorContains != "" {
				found := false
				for _, err := range result.Errors {
					if strings.Contains(strings.ToLower(err), strings.ToLower(tt.errorContains)) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q, got: %v", tt.errorContains, result.Errors)
			}
		})
	}
}

func TestValidatePasswordDefault(t *testing.T) {
	result := ValidatePasswordDefault("WeakPass")
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)

	result = ValidatePasswordDefault("StrongP@ss123!")
	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)
}

func TestIsCommonPassword(t *testing.T) {
	tests := []struct {
		password string
		expected bool
	}{
		{"password", true},
		{"Password123!", false}, // case-sensitive check happens elsewhere
		{"qwerty", true},
		{"admin123", true},
		{"uniqueP@ssword1", false},
		{"123456", true},
		{"iloveyou", true},
	}

	for _, tt := range tests {
		result := isCommonPassword(tt.password)
		assert.Equal(t, tt.expected, result, "password=%q", tt.password)
	}
}

func TestHasSequentialChars(t *testing.T) {
	tests := []struct {
		password  string
		minSeq    int
		expected  bool
		reasoning string
	}{
		{"abcd1234", 4, true, "contains 'abcd' and '1234'"},
		{"1234abcd", 4, true, "contains '1234' and 'abcd'"},
		{"abc123", 4, false, "sequences are only 3 chars"},
		{"qwerty123", 4, true, "contains 'qwer' keyboard sequence"},
		{"password", 4, false, "no sequential chars"},
		{"9876test", 4, true, "descending '9876'"},
		{"dcba1234", 4, true, "descending 'dcba' and ascending '1234'"},
		{"randomStrongP@ss", 4, false, "no sequences"},
	}

	for _, tt := range tests {
		result := hasSequentialChars(tt.password, tt.minSeq)
		assert.Equal(t, tt.expected, result, "password=%q: %s", tt.password, tt.reasoning)
	}
}

func TestHasRepeatedChars(t *testing.T) {
	tests := []struct {
		password   string
		maxRepeats int
		expected   bool
	}{
		{"aaaa1234", 4, true},
		{"aaa1234", 4, false},
		{"passssword", 4, true},
		{"password", 4, false},
		{"11111", 4, true},
		{"1111", 4, true},
		{"111", 4, false},
		{"noRepeats", 4, false},
	}

	for _, tt := range tests {
		result := hasRepeatedChars(tt.password, tt.maxRepeats)
		assert.Equal(t, tt.expected, result, "password=%q, maxRepeats=%d", tt.password, tt.maxRepeats)
	}
}

func TestDefaultPasswordRequirements(t *testing.T) {
	req := DefaultPasswordRequirements()

	assert.Equal(t, 8, req.MinLength)
	assert.Equal(t, 128, req.MaxLength)
	assert.True(t, req.RequireUppercase)
	assert.True(t, req.RequireLowercase)
	assert.True(t, req.RequireDigit)
	assert.True(t, req.RequireSpecial)
	assert.True(t, req.DisallowCommon)
	assert.True(t, req.DisallowSequence)
}

func TestValidatePasswordCustomRequirements(t *testing.T) {
	// Test with relaxed requirements
	relaxedReq := PasswordRequirements{
		MinLength:        6,
		MaxLength:        50,
		RequireUppercase: false,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   false,
		DisallowCommon:   false,
		DisallowSequence: false,
	}

	// This would fail default but pass relaxed
	result := ValidatePassword("simple123", relaxedReq)
	assert.True(t, result.Valid)

	// Test max length
	longPassword := strings.Repeat("a", 51)
	result = ValidatePassword(longPassword, relaxedReq)
	assert.False(t, result.Valid)
	assert.Contains(t, result.Errors[0], "at most 50 characters")
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{8, "8"},
	}

	for _, tt := range tests {
		result := itoa(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}
