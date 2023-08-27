// Code generated by ent, DO NOT EDIT.

package did

import (
	"time"
)

const (
	// Label holds the string label denoting the did type in the database.
	Label = "did"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldPrivatekey holds the string denoting the privatekey field in the database.
	FieldPrivatekey = "privatekey"
	// FieldMethod holds the string denoting the method field in the database.
	FieldMethod = "method"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// Table holds the table name of the did in the database.
	Table = "di_ds"
	// UserTable is the table that holds the user relation/edge.
	UserTable = "di_ds"
	// UserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UserInverseTable = "users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "user_dids"
)

// Columns holds all SQL columns for did fields.
var Columns = []string{
	FieldID,
	FieldPrivatekey,
	FieldMethod,
	FieldCreatedAt,
	FieldUpdatedAt,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "di_ds"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"user_dids",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultUpdatedAt holds the default value on creation for the "updated_at" field.
	DefaultUpdatedAt func() time.Time
)
