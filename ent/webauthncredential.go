// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/hesusruiz/vcbackend/ent/user"
	"github.com/hesusruiz/vcbackend/ent/webauthncredential"
)

// WebauthnCredential is the model entity for the WebauthnCredential schema.
type WebauthnCredential struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id,omitempty"`
	// CreateTime holds the value of the "create_time" field.
	CreateTime time.Time `json:"create_time,omitempty"`
	// UpdateTime holds the value of the "update_time" field.
	UpdateTime time.Time `json:"update_time,omitempty"`
	// Credential holds the value of the "credential" field.
	Credential webauthn.Credential `json:"credential,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the WebauthnCredentialQuery when eager-loading is set.
	Edges                 WebauthnCredentialEdges `json:"edges"`
	user_authncredentials *string
}

// WebauthnCredentialEdges holds the relations/edges for other nodes in the graph.
type WebauthnCredentialEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e WebauthnCredentialEdges) UserOrErr() (*User, error) {
	if e.loadedTypes[0] {
		if e.User == nil {
			// The edge user was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: user.Label}
		}
		return e.User, nil
	}
	return nil, &NotLoadedError{edge: "user"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*WebauthnCredential) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case webauthncredential.FieldCredential:
			values[i] = new([]byte)
		case webauthncredential.FieldID:
			values[i] = new(sql.NullString)
		case webauthncredential.FieldCreateTime, webauthncredential.FieldUpdateTime:
			values[i] = new(sql.NullTime)
		case webauthncredential.ForeignKeys[0]: // user_authncredentials
			values[i] = new(sql.NullString)
		default:
			return nil, fmt.Errorf("unexpected column %q for type WebauthnCredential", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the WebauthnCredential fields.
func (wc *WebauthnCredential) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case webauthncredential.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				wc.ID = value.String
			}
		case webauthncredential.FieldCreateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				wc.CreateTime = value.Time
			}
		case webauthncredential.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				wc.UpdateTime = value.Time
			}
		case webauthncredential.FieldCredential:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field credential", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &wc.Credential); err != nil {
					return fmt.Errorf("unmarshal field credential: %w", err)
				}
			}
		case webauthncredential.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field user_authncredentials", values[i])
			} else if value.Valid {
				wc.user_authncredentials = new(string)
				*wc.user_authncredentials = value.String
			}
		}
	}
	return nil
}

// QueryUser queries the "user" edge of the WebauthnCredential entity.
func (wc *WebauthnCredential) QueryUser() *UserQuery {
	return (&WebauthnCredentialClient{config: wc.config}).QueryUser(wc)
}

// Update returns a builder for updating this WebauthnCredential.
// Note that you need to call WebauthnCredential.Unwrap() before calling this method if this WebauthnCredential
// was returned from a transaction, and the transaction was committed or rolled back.
func (wc *WebauthnCredential) Update() *WebauthnCredentialUpdateOne {
	return (&WebauthnCredentialClient{config: wc.config}).UpdateOne(wc)
}

// Unwrap unwraps the WebauthnCredential entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (wc *WebauthnCredential) Unwrap() *WebauthnCredential {
	_tx, ok := wc.config.driver.(*txDriver)
	if !ok {
		panic("ent: WebauthnCredential is not a transactional entity")
	}
	wc.config.driver = _tx.drv
	return wc
}

// String implements the fmt.Stringer.
func (wc *WebauthnCredential) String() string {
	var builder strings.Builder
	builder.WriteString("WebauthnCredential(")
	builder.WriteString(fmt.Sprintf("id=%v, ", wc.ID))
	builder.WriteString("create_time=")
	builder.WriteString(wc.CreateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("update_time=")
	builder.WriteString(wc.UpdateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("credential=")
	builder.WriteString(fmt.Sprintf("%v", wc.Credential))
	builder.WriteByte(')')
	return builder.String()
}

// WebauthnCredentials is a parsable slice of WebauthnCredential.
type WebauthnCredentials []*WebauthnCredential

func (wc WebauthnCredentials) config(cfg config) {
	for _i := range wc {
		wc[_i].config = cfg
	}
}
