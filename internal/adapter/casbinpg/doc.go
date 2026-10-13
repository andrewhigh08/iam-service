// Package casbinpg persists casbin policies in the casbin_rule table of the application
// database through GORM. The table and its unique index on (ptype, v0..v5) come from the
// embedded migrations; the adapter never changes the schema.
package casbinpg
