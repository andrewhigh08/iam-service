package casbinpg

import (
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testModel is an RBAC model with two policy types, to check the order rules are saved in.
const testModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act
p2 = sub, obj

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func TestNewRow(t *testing.T) {
	t.Parallel()

	r, err := newRow("p", []string{"role:admin", "users", "read"})
	require.NoError(t, err)
	assert.Equal(t, row{Ptype: "p", V0: "role:admin", V1: "users", V2: "read"}, r)

	full, err := newRow("p", []string{"0", "1", "2", "3", "4", "5"})
	require.NoError(t, err)
	assert.Equal(t, row{Ptype: "p", V0: "0", V1: "1", V2: "2", V3: "3", V4: "4", V5: "5"}, full)

	_, err = newRow("p", []string{"0", "1", "2", "3", "4", "5", "6"})
	require.ErrorContains(t, err, "at most 6")
}

func TestTokensDropTrailingEmptyValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		row  row
		want []string
	}{
		{"three values", row{Ptype: "p", V0: "role:admin", V1: "users", V2: "read"}, []string{"p", "role:admin", "users", "read"}},
		{"no values", row{Ptype: "g"}, []string{"g"}},
		{"inner empty value is kept", row{Ptype: "p", V0: "a", V2: "c"}, []string{"p", "a", "", "c"}},
		{"all six values", row{Ptype: "p", V0: "0", V1: "1", V2: "2", V3: "3", V4: "4", V5: "5"}, []string{"p", "0", "1", "2", "3", "4", "5"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.row.tokens())
		})
	}
}

func TestConditionsCompareEveryValue(t *testing.T) {
	t.Parallel()

	r, err := newRow("g", []string{"user:1", "role:admin"})
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"ptype": "g", "v0": "user:1", "v1": "role:admin", "v2": "", "v3": "", "v4": "", "v5": "",
	}, r.conditions())
}

func TestFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		fieldIndex int
		values     []string
		want       map[string]any
		wantErr    string
	}{
		{"first field", 0, []string{"role:admin"}, map[string]any{"ptype": "p", "v0": "role:admin"}, ""},
		{"empty value matches anything", 1, []string{"", "read"}, map[string]any{"ptype": "p", "v2": "read"}, ""},
		{"last field", 5, []string{"x"}, map[string]any{"ptype": "p", "v5": "x"}, ""},
		{"no values", 0, nil, nil, "at least one value"},
		{"only empty values", 0, []string{"", ""}, nil, "at least one value"},
		{"negative index", -1, []string{"x"}, nil, "outside"},
		{"past the last field", 5, []string{"x", "y"}, nil, "outside"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := filter("p", tt.fieldIndex, tt.values)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRowsOfWritesPoliciesThenGroupings(t *testing.T) {
	t.Parallel()
	m, err := model.NewModelFromString(testModel)
	require.NoError(t, err)
	require.NoError(t, m.AddPolicy("g", "g", []string{"user:1", "role:admin"}))
	require.NoError(t, m.AddPolicy("p", "p2", []string{"role:admin", "audit"}))
	require.NoError(t, m.AddPolicy("p", "p", []string{"role:admin", "users", "read"}))
	require.NoError(t, m.AddPolicy("p", "p", []string{"role:admin", "users", "write"}))

	rows, err := rowsOf(m)
	require.NoError(t, err)

	assert.Equal(t, []row{
		{Ptype: "p", V0: "role:admin", V1: "users", V2: "read"},
		{Ptype: "p", V0: "role:admin", V1: "users", V2: "write"},
		{Ptype: "p2", V0: "role:admin", V1: "audit"},
		{Ptype: "g", V0: "user:1", V1: "role:admin"},
	}, rows)

	empty, err := rowsOf(model.NewModel())
	require.NoError(t, err)
	assert.Empty(t, empty)
}
