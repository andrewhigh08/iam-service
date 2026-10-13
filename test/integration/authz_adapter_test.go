package integration

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/andrewhigh08/iam-service/internal/adapter/casbinpg"
	"github.com/andrewhigh08/iam-service/internal/adapter/pgrepo"
	"github.com/andrewhigh08/iam-service/migrations"
)

// ruleColumns is the number of columns a stored rule spans: the type and six values.
const ruleColumns = 7

// policyDB is a migrated database of its own for one adapter test: emptying its casbin_rule
// table touches neither the application under test nor another test.
type policyDB struct {
	adapter *casbinpg.Adapter
	sql     *sql.DB
}

func newPolicyDB(t *testing.T, s *suite) *policyDB {
	t.Helper()
	name := strings.ReplaceAll(uniquePrefix(t), "-", "_")
	control := openDB(t, s, postgresDB)
	_, err := control.ExecContext(t.Context(), "CREATE DATABASE "+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), teardownTimeout)
		defer cancel()
		_, dropErr := control.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		assert.NoError(t, dropErr)
	})

	db := openDB(t, s, name)
	require.NoError(t, pgrepo.Migrate(t.Context(), db, migrations.FS))
	g, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	return &policyDB{adapter: casbinpg.New(g), sql: db}
}

// rules returns the stored rules oldest first, each as its type followed by the six value
// columns; a NULL, which the adapter never writes, reads as "<null>".
func (p *policyDB) rules(t *testing.T) [][]string {
	t.Helper()
	rows, err := p.sql.QueryContext(t.Context(), "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rule ORDER BY id")
	require.NoError(t, err)
	defer rows.Close()

	var out [][]string
	for rows.Next() {
		var cols [ruleColumns]sql.NullString
		require.NoError(t, rows.Scan(&cols[0], &cols[1], &cols[2], &cols[3], &cols[4], &cols[5], &cols[6]))
		stored := make([]string, len(cols))
		for i, c := range cols {
			stored[i] = c.String
			if !c.Valid {
				stored[i] = "<null>"
			}
		}
		out = append(out, stored)
	}
	require.NoError(t, rows.Err())
	return out
}

// stored is the row expected for a rule: its type, its values and empty strings for the rest.
func stored(ptype string, values ...string) []string {
	r := append([]string{ptype}, values...)
	for len(r) < ruleColumns {
		r = append(r, "")
	}
	return r
}

// newPolicyEnforcer returns a synced enforcer on the production model, as the application
// builds it, whose changes are written through adapter at once.
func newPolicyEnforcer(t *testing.T, adapter *casbinpg.Adapter) *casbin.SyncedEnforcer {
	t.Helper()
	e, err := casbin.NewSyncedEnforcer(casbinModelPath, adapter)
	require.NoError(t, err)
	e.EnableAutoSave(true)
	return e
}

func newPolicyModel(t *testing.T) model.Model {
	t.Helper()
	m, err := model.NewModelFromFile(casbinModelPath)
	require.NoError(t, err)
	return m
}

func policies(t *testing.T, m model.Model, sec, ptype string) [][]string {
	t.Helper()
	rules, err := m.GetPolicy(sec, ptype)
	require.NoError(t, err)
	return rules
}

func TestPolicyAdapterLoadsStoredRules(t *testing.T) {
	t.Parallel()
	s := env(t)
	db := newPolicyDB(t, s)
	_, err := db.sql.ExecContext(t.Context(), `
		INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES
			('p', 'role:admin', 'users', 'read', '', '', ''),
			('g', 'user:1', 'role:admin', '', '', '', ''),
			('p', 'role:viewer', 'users', 'read', NULL, NULL, NULL)`)
	require.NoError(t, err)

	m := newPolicyModel(t)
	require.NoError(t, db.adapter.LoadPolicy(m))
	assert.Equal(t, [][]string{{"role:admin", "users", "read"}, {"role:viewer", "users", "read"}}, policies(t, m, "p", "p"),
		"trailing empty and NULL values are dropped")
	assert.Equal(t, [][]string{{"user:1", "role:admin"}}, policies(t, m, "g", "g"))

	// An enforcer built on the adapter decides from the stored rules.
	e := newPolicyEnforcer(t, db.adapter)
	allowed, err := e.Enforce("user:1", "users", "read")
	require.NoError(t, err)
	assert.True(t, allowed)
	allowed, err = e.Enforce("user:1", "users", "write")
	require.NoError(t, err)
	assert.False(t, allowed)

	// A row the model cannot hold fails the load and names the row.
	_, err = db.sql.ExecContext(t.Context(),
		"INSERT INTO casbin_rule (ptype, v0, v1, v2, v3) VALUES ('p', 'role:admin', 'users', 'read', 'extra')")
	require.NoError(t, err)
	err = db.adapter.LoadPolicy(newPolicyModel(t))
	require.ErrorContains(t, err, "failed to load policy row")
}

func TestPolicyAdapterAddsAndRemovesRules(t *testing.T) {
	t.Parallel()
	s := env(t)
	db := newPolicyDB(t, s)
	e := newPolicyEnforcer(t, db.adapter)

	added, err := e.AddPolicy("role:admin", "users", "read")
	require.NoError(t, err)
	assert.True(t, added)
	added, err = e.AddGroupingPolicy("user:7", "role:admin")
	require.NoError(t, err)
	assert.True(t, added)
	assert.Equal(t, [][]string{stored("p", "role:admin", "users", "read"), stored("g", "user:7", "role:admin")}, db.rules(t))

	// Storing a rule again is not an error and does not duplicate it.
	require.NoError(t, db.adapter.AddPolicy("p", "p", []string{"role:admin", "users", "read"}))
	require.NoError(t, db.adapter.AddPolicy("p", "p", []string{"role:admin", "users", "read"}))
	assert.Len(t, db.rules(t), 2)

	// A rule is matched on every value: removing a prefix of a rule leaves the rule alone, and
	// removing a rule that is not stored is not an error.
	require.NoError(t, db.adapter.AddPolicy("p", "p", []string{"role:admin", "users"}))
	require.NoError(t, db.adapter.RemovePolicy("p", "p", []string{"role:admin", "users"}))
	require.NoError(t, db.adapter.RemovePolicy("p", "p", []string{"role:admin", "users", "nothing"}))
	assert.Equal(t, [][]string{stored("p", "role:admin", "users", "read"), stored("g", "user:7", "role:admin")}, db.rules(t))

	// Another enforcer on the same table, as another replica would be, sees the stored rules.
	other := newPolicyEnforcer(t, db.adapter)
	roles, err := other.GetRolesForUser("user:7")
	require.NoError(t, err)
	assert.Equal(t, []string{"role:admin"}, roles)
	allowed, err := other.Enforce("user:7", "users", "read")
	require.NoError(t, err)
	assert.True(t, allowed)

	removed, err := e.RemoveGroupingPolicy("user:7", "role:admin")
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = e.RemovePolicy("role:admin", "users", "read")
	require.NoError(t, err)
	assert.True(t, removed)
	assert.Empty(t, db.rules(t))
}

func TestPolicyAdapterRemovesFilteredRules(t *testing.T) {
	t.Parallel()
	s := env(t)
	db := newPolicyDB(t, s)
	e := newPolicyEnforcer(t, db.adapter)
	added, err := e.AddPolicies([][]string{
		{"role:admin", "users", "read"},
		{"role:admin", "users", "write"},
		{"role:viewer", "users", "read"},
		{"role:viewer", "audit", "read"},
	})
	require.NoError(t, err)
	assert.True(t, added)
	added, err = e.AddGroupingPolicy("user:1", "role:viewer")
	require.NoError(t, err)
	assert.True(t, added)

	// The values from the index on are matched, an empty value matching anything.
	require.NoError(t, db.adapter.RemoveFilteredPolicy("p", "p", 1, "users", "read"))
	assert.Equal(t, [][]string{
		stored("p", "role:admin", "users", "write"),
		stored("p", "role:viewer", "audit", "read"),
		stored("g", "user:1", "role:viewer"),
	}, db.rules(t))
	require.NoError(t, db.adapter.RemoveFilteredPolicy("p", "p", 0, "role:viewer", "", "read"))
	assert.Equal(t, [][]string{
		stored("p", "role:admin", "users", "write"),
		stored("g", "user:1", "role:viewer"),
	}, db.rules(t))

	// A filter without a value is refused instead of emptying the policy type.
	require.ErrorContains(t, db.adapter.RemoveFilteredPolicy("p", "p", 0, "", ""), "at least one value")
	require.ErrorContains(t, db.adapter.RemoveFilteredPolicy("p", "p", 5, "a", "b"), "outside")
	assert.Len(t, db.rules(t), 2)

	// Through the enforcer, the model and the table change together.
	require.NoError(t, e.LoadPolicy())
	removed, err := e.RemoveFilteredPolicy(0, "role:admin")
	require.NoError(t, err)
	assert.True(t, removed)
	remaining, err := e.GetPolicy()
	require.NoError(t, err)
	assert.Empty(t, remaining)
	groupings, err := e.GetGroupingPolicy()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"user:1", "role:viewer"}}, groupings)
	assert.Equal(t, [][]string{stored("g", "user:1", "role:viewer")}, db.rules(t))
}

func TestPolicyAdapterWritesBatchesAtomically(t *testing.T) {
	t.Parallel()
	s := env(t)
	db := newPolicyDB(t, s)
	require.NoError(t, db.adapter.AddPolicy("p", "p", []string{"role:admin", "users", "read"}))

	// The adapter inserts 500 rules per statement: a batch of 501 whose last value the column
	// cannot hold fails in its second statement and is rolled back as a whole.
	rules := make([][]string, 0, 501)
	for i := range 500 {
		rules = append(rules, []string{"role:admin", "resource" + strconv.Itoa(i), "read"})
	}
	rules = append(rules, []string{"role:admin", strings.Repeat("x", 101), "read"})
	require.ErrorContains(t, db.adapter.AddPolicies("p", "p", rules), "failed to store policies")
	assert.Equal(t, [][]string{stored("p", "role:admin", "users", "read")}, db.rules(t))

	// A batch skips the rules already stored and keeps the rest; an empty batch is a no-op.
	require.NoError(t, db.adapter.AddPolicies("p", "p", [][]string{
		{"role:admin", "users", "read"},
		{"role:admin", "users", "write"},
		{"role:admin", "audit", "read"},
	}))
	require.NoError(t, db.adapter.AddPolicies("p", "p", nil))
	assert.Equal(t, [][]string{
		stored("p", "role:admin", "users", "read"),
		stored("p", "role:admin", "users", "write"),
		stored("p", "role:admin", "audit", "read"),
	}, db.rules(t))

	require.NoError(t, db.adapter.RemovePolicies("p", "p", [][]string{
		{"role:admin", "users", "read"},
		{"role:admin", "audit", "read"},
		{"role:admin", "audit", "missing"},
	}))
	assert.Equal(t, [][]string{stored("p", "role:admin", "users", "write")}, db.rules(t))

	// Through the enforcer, batches of grouping rules reach the table too.
	e := newPolicyEnforcer(t, db.adapter)
	added, err := e.AddGroupingPolicies([][]string{{"user:1", "role:admin"}, {"user:2", "role:admin"}})
	require.NoError(t, err)
	assert.True(t, added)
	removed, err := e.RemoveGroupingPolicies([][]string{{"user:1", "role:admin"}})
	require.NoError(t, err)
	assert.True(t, removed)
	assert.Equal(t, [][]string{stored("p", "role:admin", "users", "write"), stored("g", "user:2", "role:admin")}, db.rules(t))
}

func TestPolicyAdapterSavePolicyReplacesTheTable(t *testing.T) {
	t.Parallel()
	s := env(t)
	db := newPolicyDB(t, s)
	require.NoError(t, db.adapter.AddPolicy("p", "p", []string{"role:stale", "users", "read"}))

	m := newPolicyModel(t)
	require.NoError(t, m.AddPolicy("g", "g", []string{"user:1", "role:admin"}))
	require.NoError(t, m.AddPolicy("p", "p", []string{"role:admin", "users", "write"}))
	require.NoError(t, m.AddPolicy("p", "p", []string{"role:admin", "users", "read"}))
	require.NoError(t, db.adapter.SavePolicy(m))
	assert.Equal(t, [][]string{
		stored("p", "role:admin", "users", "write"),
		stored("p", "role:admin", "users", "read"),
		stored("g", "user:1", "role:admin"),
	}, db.rules(t))

	// What was saved loads back as it was.
	loaded := newPolicyModel(t)
	require.NoError(t, db.adapter.LoadPolicy(loaded))
	assert.Equal(t, policies(t, m, "p", "p"), policies(t, loaded, "p", "p"))
	assert.Equal(t, policies(t, m, "g", "g"), policies(t, loaded, "g", "g"))

	// Saving an enforcer whose policy was cleared empties the table.
	e := newPolicyEnforcer(t, db.adapter)
	e.ClearPolicy()
	require.NoError(t, e.SavePolicy())
	assert.Empty(t, db.rules(t))
}
