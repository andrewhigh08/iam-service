package casbinpg

import (
	"fmt"
	"maps"
	"slices"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// Layout of the casbin_rule table: a policy type and up to six rule values.
const (
	tableName   = "casbin_rule"
	maxValues   = 6
	insertBatch = 500
)

// loadColumns reads a row with a NULL, which only a row inserted by hand can hold, as empty.
const loadColumns = "id, COALESCE(ptype, '') AS ptype, COALESCE(v0, '') AS v0, COALESCE(v1, '') AS v1, " +
	"COALESCE(v2, '') AS v2, COALESCE(v3, '') AS v3, COALESCE(v4, '') AS v4, COALESCE(v5, '') AS v5"

// sections are the model sections whose rules are persisted, in the order SavePolicy writes them.
var sections = []string{"p", "g"}

var valueColumns = [maxValues]string{"v0", "v1", "v2", "v3", "v4", "v5"}

// Compile-time checks that Adapter satisfies the casbin persistence interfaces.
var (
	_ persist.Adapter      = (*Adapter)(nil)
	_ persist.BatchAdapter = (*Adapter)(nil)
)

// Adapter stores casbin policies in the casbin_rule table. It keeps no state of its own, so one
// instance can serve several enforcers; the enforcer serializes the changes it makes.
type Adapter struct {
	db *gorm.DB
}

// New returns an Adapter that reads and writes policies through db.
func New(db *gorm.DB) *Adapter {
	return &Adapter{db: db}
}

// row is one record of casbin_rule. The values a rule does not use are stored as empty strings
// rather than NULL, so that the unique index rejects a duplicate rule.
type row struct {
	ID    int64  `gorm:"column:id;primaryKey"`
	Ptype string `gorm:"column:ptype"`
	V0    string `gorm:"column:v0"`
	V1    string `gorm:"column:v1"`
	V2    string `gorm:"column:v2"`
	V3    string `gorm:"column:v3"`
	V4    string `gorm:"column:v4"`
	V5    string `gorm:"column:v5"`
}

// TableName returns the table the embedded migrations created.
func (row) TableName() string {
	return tableName
}

// LoadPolicy adds every stored rule to m, oldest first.
func (a *Adapter) LoadPolicy(m model.Model) error {
	var rows []row
	if err := a.db.Select(loadColumns).Order("id").Find(&rows).Error; err != nil {
		return apperror.Internal("failed to load policies", err)
	}
	for _, r := range rows {
		if r.Ptype == "" {
			return apperror.Internal(fmt.Sprintf("policy row %d has no policy type", r.ID), nil)
		}
		if err := persist.LoadPolicyArray(r.tokens(), m); err != nil {
			return apperror.Internal(fmt.Sprintf("failed to load policy row %d", r.ID), err)
		}
	}
	return nil
}

// SavePolicy replaces the stored rules with those of m in one transaction: the table is emptied,
// then the rules of the p and g sections are inserted, policy types in sorted order.
func (a *Adapter) SavePolicy(m model.Model) error {
	rows, err := rowsOf(m)
	if err != nil {
		return err
	}
	if err := a.db.Transaction(func(tx *gorm.DB) error { return replace(tx, rows) }); err != nil {
		return apperror.Internal("failed to save policies", err)
	}
	return nil
}

// AddPolicy stores rule under ptype; a rule already stored is left as it is.
func (a *Adapter) AddPolicy(_, ptype string, rule []string) error {
	return a.AddPolicies("", ptype, [][]string{rule})
}

// AddPolicies stores rules under ptype in one transaction, leaving the ones already stored as
// they are.
func (a *Adapter) AddPolicies(_, ptype string, rules [][]string) error {
	rows, err := rowsOfRules(ptype, rules)
	if err != nil {
		return err
	}
	if err := a.db.Transaction(func(tx *gorm.DB) error { return insert(tx, rows) }); err != nil {
		return apperror.Internal("failed to store policies", err)
	}
	return nil
}

// RemovePolicy deletes rule from ptype.
func (a *Adapter) RemovePolicy(_, ptype string, rule []string) error {
	return a.RemovePolicies("", ptype, [][]string{rule})
}

// RemovePolicies deletes rules from ptype in one transaction. Every value takes part in the
// match, unused ones as empty strings, so a rule never removes the longer rules it is a prefix of.
func (a *Adapter) RemovePolicies(_, ptype string, rules [][]string) error {
	rows, err := rowsOfRules(ptype, rules)
	if err != nil {
		return err
	}
	if err := a.db.Transaction(func(tx *gorm.DB) error { return remove(tx, rows) }); err != nil {
		return apperror.Internal("failed to remove policies", err)
	}
	return nil
}

// RemoveFilteredPolicy deletes the rules of ptype whose values from fieldIndex on equal
// fieldValues, an empty value matching anything. At least one value is required, so a filter
// cannot empty a policy type by accident.
func (a *Adapter) RemoveFilteredPolicy(_, ptype string, fieldIndex int, fieldValues ...string) error {
	conditions, err := filter(ptype, fieldIndex, fieldValues)
	if err != nil {
		return err
	}
	if err := a.db.Where(conditions).Delete(&row{}).Error; err != nil {
		return apperror.Internal("failed to remove policies", err)
	}
	return nil
}

func replace(tx *gorm.DB, rows []row) error {
	if err := tx.Exec("DELETE FROM casbin_rule").Error; err != nil {
		return err
	}
	return insert(tx, rows)
}

// insert adds rows in batches, skipping the ones the unique index already holds.
func insert(tx *gorm.DB, rows []row) error {
	for batch := range slices.Chunk(rows, insertBatch) {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&batch).Error; err != nil {
			return err
		}
	}
	return nil
}

func remove(tx *gorm.DB, rows []row) error {
	for _, r := range rows {
		if err := tx.Where(r.conditions()).Delete(&row{}).Error; err != nil {
			return err
		}
	}
	return nil
}

// rowsOf returns the rules of the p and g sections of m as rows, policy types in sorted order.
func rowsOf(m model.Model) ([]row, error) {
	var rows []row
	for _, sec := range sections {
		for _, ptype := range slices.Sorted(maps.Keys(m[sec])) {
			for _, rule := range m[sec][ptype].Policy {
				r, err := newRow(ptype, rule)
				if err != nil {
					return nil, err
				}
				rows = append(rows, r)
			}
		}
	}
	return rows, nil
}

func rowsOfRules(ptype string, rules [][]string) ([]row, error) {
	rows := make([]row, 0, len(rules))
	for _, rule := range rules {
		r, err := newRow(ptype, rule)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func newRow(ptype string, rule []string) (row, error) {
	if len(rule) > maxValues {
		return row{}, apperror.Internal(fmt.Sprintf(
			"policy rule has %d values, the table holds at most %d", len(rule), maxValues), nil)
	}
	var v [maxValues]string
	copy(v[:], rule)
	return row{Ptype: ptype, V0: v[0], V1: v[1], V2: v[2], V3: v[3], V4: v[4], V5: v[5]}, nil
}

func (r row) values() [maxValues]string {
	return [maxValues]string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
}

// tokens returns the policy line of r as casbin reads it: the type, then the values up to the
// last non-empty one.
func (r row) tokens() []string {
	values := r.values()
	n := maxValues
	for n > 0 && values[n-1] == "" {
		n--
	}
	return append([]string{r.Ptype}, values[:n]...)
}

func (r row) conditions() map[string]any {
	conditions := map[string]any{"ptype": r.Ptype}
	for i, v := range r.values() {
		conditions[valueColumns[i]] = v
	}
	return conditions
}

func filter(ptype string, fieldIndex int, fieldValues []string) (map[string]any, error) {
	if fieldIndex < 0 || fieldIndex+len(fieldValues) > maxValues {
		return nil, apperror.Internal(fmt.Sprintf(
			"policy filter at field %d with %d values is outside the %d rule values", fieldIndex, len(fieldValues), maxValues), nil)
	}
	conditions := map[string]any{"ptype": ptype}
	for i, v := range fieldValues {
		if v != "" {
			conditions[valueColumns[fieldIndex+i]] = v
		}
	}
	if len(conditions) == 1 {
		return nil, apperror.Internal("policy filter needs at least one value", nil)
	}
	return conditions, nil
}
