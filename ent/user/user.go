// Code generated by ent, DO NOT EDIT.

package user

import (
	"time"
)

const (
	// Label holds the string label denoting the user type in the database.
	Label = "user"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldDisplayname holds the string denoting the displayname field in the database.
	FieldDisplayname = "displayname"
	// FieldType holds the string denoting the type field in the database.
	FieldType = "type"
	// FieldPassword holds the string denoting the password field in the database.
	FieldPassword = "password"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// EdgeKeys holds the string denoting the keys edge name in mutations.
	EdgeKeys = "keys"
	// EdgeDids holds the string denoting the dids edge name in mutations.
	EdgeDids = "dids"
	// EdgeCredentials holds the string denoting the credentials edge name in mutations.
	EdgeCredentials = "credentials"
	// EdgeAuthncredentials holds the string denoting the authncredentials edge name in mutations.
	EdgeAuthncredentials = "authncredentials"
	// Table holds the table name of the user in the database.
	Table = "users"
	// KeysTable is the table that holds the keys relation/edge.
	KeysTable = "private_keys"
	// KeysInverseTable is the table name for the PrivateKey entity.
	// It exists in this package in order to avoid circular dependency with the "privatekey" package.
	KeysInverseTable = "private_keys"
	// KeysColumn is the table column denoting the keys relation/edge.
	KeysColumn = "user_keys"
	// DidsTable is the table that holds the dids relation/edge.
	DidsTable = "di_ds"
	// DidsInverseTable is the table name for the DID entity.
	// It exists in this package in order to avoid circular dependency with the "did" package.
	DidsInverseTable = "di_ds"
	// DidsColumn is the table column denoting the dids relation/edge.
	DidsColumn = "user_dids"
	// CredentialsTable is the table that holds the credentials relation/edge.
	CredentialsTable = "credentials"
	// CredentialsInverseTable is the table name for the Credential entity.
	// It exists in this package in order to avoid circular dependency with the "credential" package.
	CredentialsInverseTable = "credentials"
	// CredentialsColumn is the table column denoting the credentials relation/edge.
	CredentialsColumn = "user_credentials"
	// AuthncredentialsTable is the table that holds the authncredentials relation/edge.
	AuthncredentialsTable = "webauthn_credentials"
	// AuthncredentialsInverseTable is the table name for the WebauthnCredential entity.
	// It exists in this package in order to avoid circular dependency with the "webauthncredential" package.
	AuthncredentialsInverseTable = "webauthn_credentials"
	// AuthncredentialsColumn is the table column denoting the authncredentials relation/edge.
	AuthncredentialsColumn = "user_authncredentials"
)

// Columns holds all SQL columns for user fields.
var Columns = []string{
	FieldID,
	FieldName,
	FieldDisplayname,
	FieldType,
	FieldPassword,
	FieldCreatedAt,
	FieldUpdatedAt,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// NameValidator is a validator for the "name" field. It is called by the builders before save.
	NameValidator func(string) error
	// TypeValidator is a validator for the "type" field. It is called by the builders before save.
	TypeValidator func(string) error
	// PasswordValidator is a validator for the "password" field. It is called by the builders before save.
	PasswordValidator func([]byte) error
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultUpdatedAt holds the default value on creation for the "updated_at" field.
	DefaultUpdatedAt func() time.Time
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)
