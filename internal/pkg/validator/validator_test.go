package validator

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// violations extracts Details["errors"] from a validation error after checking its shape.
func violations(t *testing.T, err error) []string {
	t.Helper()
	var appErr *apperror.AppError
	require.ErrorAs(t, err, &appErr, "error must be an *apperror.AppError, got %T", err)
	assert.Equal(t, apperror.CodeValidation, appErr.Code)
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
	assert.Equal(t, "password does not meet the policy", appErr.Message)
	list, ok := appErr.Details["errors"].([]string)
	require.True(t, ok, "Details[\"errors\"] must be a []string, got %T", appErr.Details["errors"])
	return list
}

func TestValidatePassword_DefaultPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []string // substrings of the expected violations, in order; empty means valid
	}{
		{name: "valid ascii", in: "Str0ng!Pass"},
		{name: "valid greek", in: "Κωδικός123!"},
		{name: "valid with space as filler", in: "Correct Horse 1!"},
		{name: "exactly eight characters", in: "Aa1!Aa1!"},
		{name: "exactly 72 bytes ascii", in: strings.Repeat("Aa1!", 18)},
		{name: "unicode symbol counts as special", in: "Strong1€Pass"},
		{name: "punctuation counts as special", in: "Strong1.Pass"},
		{name: "seven characters", in: "Aa1!Aa1", want: []string{"at least 8 characters"}},
		{name: "too short", in: "Ab1!", want: []string{"at least 8 characters"}},
		{name: "no uppercase", in: "strong1!pass", want: []string{"uppercase"}},
		{name: "no lowercase", in: "STRONG1!PASS", want: []string{"lowercase"}},
		{name: "no digit", in: "Strong!Pass", want: []string{"digit"}},
		{name: "no special", in: "Strong1Pass", want: []string{"special"}},
		{name: "space is not a special character", in: "Strong1 Pass", want: []string{"special"}},
		{name: "common despite meeting every class", in: "P@ssw0rd", want: []string{"too common"}},
		{name: "common is case-insensitive", in: "PASSWORD", want: []string{"lowercase", "digit", "special", "too common"}},
		{name: "digits only", in: "12345678", want: []string{"uppercase", "lowercase", "special", "too common"}},
		{name: "spaces only", in: strings.Repeat(" ", 8), want: []string{"uppercase", "lowercase", "digit", "special"}},
		{name: "over 72 bytes ascii", in: strings.Repeat("Aa1!", 19), want: []string{"72 bytes"}},
		{name: "over 72 bytes greek within character limit", in: "Κωδικός1!" + strings.Repeat("ω", 40), want: []string{"72 bytes"}},
		{name: "over max characters", in: strings.Repeat("Aa1!", 33), want: []string{"at most 128 characters", "72 bytes"}},
		{name: "empty", in: "", want: []string{"at least 8", "uppercase", "lowercase", "digit", "special"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePassword(tt.in, DefaultPolicy())
			if len(tt.want) == 0 {
				assert.NoError(t, err)
				return
			}

			got := violations(t, err)
			require.Len(t, got, len(tt.want), "violations: %v", got)
			for i, want := range tt.want {
				assert.Contains(t, got[i], want)
			}
		})
	}
}

func TestValidatePassword_ValidReturnsUntypedNil(t *testing.T) {
	t.Parallel()
	err := ValidatePassword("Str0ng!Pass", DefaultPolicy())
	assert.NoError(t, err)
}

func TestValidatePassword_CustomPolicy(t *testing.T) {
	t.Parallel()
	relaxed := Policy{MinLength: 4}

	assert.NoError(t, ValidatePassword("abcd", relaxed))
	assert.NoError(t, ValidatePassword("password", relaxed), "common passwords pass when ForbidCommon is off")

	got := violations(t, ValidatePassword("abc", relaxed))
	assert.Equal(t, []string{"password must be at least 4 characters long"}, got)

	strict := Policy{MinLength: 1, MaxLength: 4}
	got = violations(t, ValidatePassword("abcde", strict))
	assert.Equal(t, []string{"password must be at most 4 characters long"}, got)

	digits := Policy{RequireDigit: true}
	got = violations(t, ValidatePassword("letters", digits))
	assert.Equal(t, []string{"password must contain a digit"}, got, "character classes are required individually")
}

func TestValidatePassword_ByteLimitAppliesToEveryPolicy(t *testing.T) {
	t.Parallel()
	got := violations(t, ValidatePassword(strings.Repeat("a", MaxPasswordBytes+1), Policy{}))
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "72 bytes")

	assert.NoError(t, ValidatePassword(strings.Repeat("a", MaxPasswordBytes), Policy{}))
}

func TestDefaultPolicy(t *testing.T) {
	t.Parallel()
	p := DefaultPolicy()

	assert.Equal(t, 8, p.MinLength)
	assert.Equal(t, 128, p.MaxLength)
	assert.True(t, p.RequireUpper && p.RequireLower && p.RequireDigit && p.RequireSpecial && p.ForbidCommon)
}
