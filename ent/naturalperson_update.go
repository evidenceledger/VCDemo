// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/hesusruiz/vcbackend/ent/credential"
	"github.com/hesusruiz/vcbackend/ent/naturalperson"
	"github.com/hesusruiz/vcbackend/ent/predicate"
	"github.com/hesusruiz/vcbackend/ent/privatekey"
)

// NaturalPersonUpdate is the builder for updating NaturalPerson entities.
type NaturalPersonUpdate struct {
	config
	hooks    []Hook
	mutation *NaturalPersonMutation
}

// Where appends a list predicates to the NaturalPersonUpdate builder.
func (npu *NaturalPersonUpdate) Where(ps ...predicate.NaturalPerson) *NaturalPersonUpdate {
	npu.mutation.Where(ps...)
	return npu
}

// SetName sets the "name" field.
func (npu *NaturalPersonUpdate) SetName(s string) *NaturalPersonUpdate {
	npu.mutation.SetName(s)
	return npu
}

// SetDisplayname sets the "displayname" field.
func (npu *NaturalPersonUpdate) SetDisplayname(s string) *NaturalPersonUpdate {
	npu.mutation.SetDisplayname(s)
	return npu
}

// SetNillableDisplayname sets the "displayname" field if the given value is not nil.
func (npu *NaturalPersonUpdate) SetNillableDisplayname(s *string) *NaturalPersonUpdate {
	if s != nil {
		npu.SetDisplayname(*s)
	}
	return npu
}

// ClearDisplayname clears the value of the "displayname" field.
func (npu *NaturalPersonUpdate) ClearDisplayname() *NaturalPersonUpdate {
	npu.mutation.ClearDisplayname()
	return npu
}

// SetType sets the "type" field.
func (npu *NaturalPersonUpdate) SetType(s string) *NaturalPersonUpdate {
	npu.mutation.SetType(s)
	return npu
}

// SetPassword sets the "password" field.
func (npu *NaturalPersonUpdate) SetPassword(b []byte) *NaturalPersonUpdate {
	npu.mutation.SetPassword(b)
	return npu
}

// SetUpdatedAt sets the "updated_at" field.
func (npu *NaturalPersonUpdate) SetUpdatedAt(t time.Time) *NaturalPersonUpdate {
	npu.mutation.SetUpdatedAt(t)
	return npu
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (npu *NaturalPersonUpdate) SetNillableUpdatedAt(t *time.Time) *NaturalPersonUpdate {
	if t != nil {
		npu.SetUpdatedAt(*t)
	}
	return npu
}

// AddKeyIDs adds the "keys" edge to the PrivateKey entity by IDs.
func (npu *NaturalPersonUpdate) AddKeyIDs(ids ...string) *NaturalPersonUpdate {
	npu.mutation.AddKeyIDs(ids...)
	return npu
}

// AddKeys adds the "keys" edges to the PrivateKey entity.
func (npu *NaturalPersonUpdate) AddKeys(p ...*PrivateKey) *NaturalPersonUpdate {
	ids := make([]string, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return npu.AddKeyIDs(ids...)
}

// AddCredentialIDs adds the "credentials" edge to the Credential entity by IDs.
func (npu *NaturalPersonUpdate) AddCredentialIDs(ids ...string) *NaturalPersonUpdate {
	npu.mutation.AddCredentialIDs(ids...)
	return npu
}

// AddCredentials adds the "credentials" edges to the Credential entity.
func (npu *NaturalPersonUpdate) AddCredentials(c ...*Credential) *NaturalPersonUpdate {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return npu.AddCredentialIDs(ids...)
}

// Mutation returns the NaturalPersonMutation object of the builder.
func (npu *NaturalPersonUpdate) Mutation() *NaturalPersonMutation {
	return npu.mutation
}

// ClearKeys clears all "keys" edges to the PrivateKey entity.
func (npu *NaturalPersonUpdate) ClearKeys() *NaturalPersonUpdate {
	npu.mutation.ClearKeys()
	return npu
}

// RemoveKeyIDs removes the "keys" edge to PrivateKey entities by IDs.
func (npu *NaturalPersonUpdate) RemoveKeyIDs(ids ...string) *NaturalPersonUpdate {
	npu.mutation.RemoveKeyIDs(ids...)
	return npu
}

// RemoveKeys removes "keys" edges to PrivateKey entities.
func (npu *NaturalPersonUpdate) RemoveKeys(p ...*PrivateKey) *NaturalPersonUpdate {
	ids := make([]string, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return npu.RemoveKeyIDs(ids...)
}

// ClearCredentials clears all "credentials" edges to the Credential entity.
func (npu *NaturalPersonUpdate) ClearCredentials() *NaturalPersonUpdate {
	npu.mutation.ClearCredentials()
	return npu
}

// RemoveCredentialIDs removes the "credentials" edge to Credential entities by IDs.
func (npu *NaturalPersonUpdate) RemoveCredentialIDs(ids ...string) *NaturalPersonUpdate {
	npu.mutation.RemoveCredentialIDs(ids...)
	return npu
}

// RemoveCredentials removes "credentials" edges to Credential entities.
func (npu *NaturalPersonUpdate) RemoveCredentials(c ...*Credential) *NaturalPersonUpdate {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return npu.RemoveCredentialIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (npu *NaturalPersonUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(npu.hooks) == 0 {
		if err = npu.check(); err != nil {
			return 0, err
		}
		affected, err = npu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*NaturalPersonMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = npu.check(); err != nil {
				return 0, err
			}
			npu.mutation = mutation
			affected, err = npu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(npu.hooks) - 1; i >= 0; i-- {
			if npu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = npu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, npu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (npu *NaturalPersonUpdate) SaveX(ctx context.Context) int {
	affected, err := npu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (npu *NaturalPersonUpdate) Exec(ctx context.Context) error {
	_, err := npu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (npu *NaturalPersonUpdate) ExecX(ctx context.Context) {
	if err := npu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (npu *NaturalPersonUpdate) check() error {
	if v, ok := npu.mutation.Name(); ok {
		if err := naturalperson.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "NaturalPerson.name": %w`, err)}
		}
	}
	if v, ok := npu.mutation.GetType(); ok {
		if err := naturalperson.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "NaturalPerson.type": %w`, err)}
		}
	}
	if v, ok := npu.mutation.Password(); ok {
		if err := naturalperson.PasswordValidator(v); err != nil {
			return &ValidationError{Name: "password", err: fmt.Errorf(`ent: validator failed for field "NaturalPerson.password": %w`, err)}
		}
	}
	return nil
}

func (npu *NaturalPersonUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   naturalperson.Table,
			Columns: naturalperson.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: naturalperson.FieldID,
			},
		},
	}
	if ps := npu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := npu.mutation.Name(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: naturalperson.FieldName,
		})
	}
	if value, ok := npu.mutation.Displayname(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: naturalperson.FieldDisplayname,
		})
	}
	if npu.mutation.DisplaynameCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Column: naturalperson.FieldDisplayname,
		})
	}
	if value, ok := npu.mutation.GetType(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: naturalperson.FieldType,
		})
	}
	if value, ok := npu.mutation.Password(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: naturalperson.FieldPassword,
		})
	}
	if value, ok := npu.mutation.UpdatedAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: naturalperson.FieldUpdatedAt,
		})
	}
	if npu.mutation.KeysCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.KeysTable,
			Columns: []string{naturalperson.KeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: privatekey.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npu.mutation.RemovedKeysIDs(); len(nodes) > 0 && !npu.mutation.KeysCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.KeysTable,
			Columns: []string{naturalperson.KeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: privatekey.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npu.mutation.KeysIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.KeysTable,
			Columns: []string{naturalperson.KeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: privatekey.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if npu.mutation.CredentialsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.CredentialsTable,
			Columns: []string{naturalperson.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: credential.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npu.mutation.RemovedCredentialsIDs(); len(nodes) > 0 && !npu.mutation.CredentialsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.CredentialsTable,
			Columns: []string{naturalperson.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: credential.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npu.mutation.CredentialsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.CredentialsTable,
			Columns: []string{naturalperson.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: credential.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, npu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{naturalperson.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// NaturalPersonUpdateOne is the builder for updating a single NaturalPerson entity.
type NaturalPersonUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *NaturalPersonMutation
}

// SetName sets the "name" field.
func (npuo *NaturalPersonUpdateOne) SetName(s string) *NaturalPersonUpdateOne {
	npuo.mutation.SetName(s)
	return npuo
}

// SetDisplayname sets the "displayname" field.
func (npuo *NaturalPersonUpdateOne) SetDisplayname(s string) *NaturalPersonUpdateOne {
	npuo.mutation.SetDisplayname(s)
	return npuo
}

// SetNillableDisplayname sets the "displayname" field if the given value is not nil.
func (npuo *NaturalPersonUpdateOne) SetNillableDisplayname(s *string) *NaturalPersonUpdateOne {
	if s != nil {
		npuo.SetDisplayname(*s)
	}
	return npuo
}

// ClearDisplayname clears the value of the "displayname" field.
func (npuo *NaturalPersonUpdateOne) ClearDisplayname() *NaturalPersonUpdateOne {
	npuo.mutation.ClearDisplayname()
	return npuo
}

// SetType sets the "type" field.
func (npuo *NaturalPersonUpdateOne) SetType(s string) *NaturalPersonUpdateOne {
	npuo.mutation.SetType(s)
	return npuo
}

// SetPassword sets the "password" field.
func (npuo *NaturalPersonUpdateOne) SetPassword(b []byte) *NaturalPersonUpdateOne {
	npuo.mutation.SetPassword(b)
	return npuo
}

// SetUpdatedAt sets the "updated_at" field.
func (npuo *NaturalPersonUpdateOne) SetUpdatedAt(t time.Time) *NaturalPersonUpdateOne {
	npuo.mutation.SetUpdatedAt(t)
	return npuo
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (npuo *NaturalPersonUpdateOne) SetNillableUpdatedAt(t *time.Time) *NaturalPersonUpdateOne {
	if t != nil {
		npuo.SetUpdatedAt(*t)
	}
	return npuo
}

// AddKeyIDs adds the "keys" edge to the PrivateKey entity by IDs.
func (npuo *NaturalPersonUpdateOne) AddKeyIDs(ids ...string) *NaturalPersonUpdateOne {
	npuo.mutation.AddKeyIDs(ids...)
	return npuo
}

// AddKeys adds the "keys" edges to the PrivateKey entity.
func (npuo *NaturalPersonUpdateOne) AddKeys(p ...*PrivateKey) *NaturalPersonUpdateOne {
	ids := make([]string, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return npuo.AddKeyIDs(ids...)
}

// AddCredentialIDs adds the "credentials" edge to the Credential entity by IDs.
func (npuo *NaturalPersonUpdateOne) AddCredentialIDs(ids ...string) *NaturalPersonUpdateOne {
	npuo.mutation.AddCredentialIDs(ids...)
	return npuo
}

// AddCredentials adds the "credentials" edges to the Credential entity.
func (npuo *NaturalPersonUpdateOne) AddCredentials(c ...*Credential) *NaturalPersonUpdateOne {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return npuo.AddCredentialIDs(ids...)
}

// Mutation returns the NaturalPersonMutation object of the builder.
func (npuo *NaturalPersonUpdateOne) Mutation() *NaturalPersonMutation {
	return npuo.mutation
}

// ClearKeys clears all "keys" edges to the PrivateKey entity.
func (npuo *NaturalPersonUpdateOne) ClearKeys() *NaturalPersonUpdateOne {
	npuo.mutation.ClearKeys()
	return npuo
}

// RemoveKeyIDs removes the "keys" edge to PrivateKey entities by IDs.
func (npuo *NaturalPersonUpdateOne) RemoveKeyIDs(ids ...string) *NaturalPersonUpdateOne {
	npuo.mutation.RemoveKeyIDs(ids...)
	return npuo
}

// RemoveKeys removes "keys" edges to PrivateKey entities.
func (npuo *NaturalPersonUpdateOne) RemoveKeys(p ...*PrivateKey) *NaturalPersonUpdateOne {
	ids := make([]string, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return npuo.RemoveKeyIDs(ids...)
}

// ClearCredentials clears all "credentials" edges to the Credential entity.
func (npuo *NaturalPersonUpdateOne) ClearCredentials() *NaturalPersonUpdateOne {
	npuo.mutation.ClearCredentials()
	return npuo
}

// RemoveCredentialIDs removes the "credentials" edge to Credential entities by IDs.
func (npuo *NaturalPersonUpdateOne) RemoveCredentialIDs(ids ...string) *NaturalPersonUpdateOne {
	npuo.mutation.RemoveCredentialIDs(ids...)
	return npuo
}

// RemoveCredentials removes "credentials" edges to Credential entities.
func (npuo *NaturalPersonUpdateOne) RemoveCredentials(c ...*Credential) *NaturalPersonUpdateOne {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return npuo.RemoveCredentialIDs(ids...)
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (npuo *NaturalPersonUpdateOne) Select(field string, fields ...string) *NaturalPersonUpdateOne {
	npuo.fields = append([]string{field}, fields...)
	return npuo
}

// Save executes the query and returns the updated NaturalPerson entity.
func (npuo *NaturalPersonUpdateOne) Save(ctx context.Context) (*NaturalPerson, error) {
	var (
		err  error
		node *NaturalPerson
	)
	if len(npuo.hooks) == 0 {
		if err = npuo.check(); err != nil {
			return nil, err
		}
		node, err = npuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*NaturalPersonMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = npuo.check(); err != nil {
				return nil, err
			}
			npuo.mutation = mutation
			node, err = npuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(npuo.hooks) - 1; i >= 0; i-- {
			if npuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = npuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, npuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*NaturalPerson)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from NaturalPersonMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (npuo *NaturalPersonUpdateOne) SaveX(ctx context.Context) *NaturalPerson {
	node, err := npuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (npuo *NaturalPersonUpdateOne) Exec(ctx context.Context) error {
	_, err := npuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (npuo *NaturalPersonUpdateOne) ExecX(ctx context.Context) {
	if err := npuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (npuo *NaturalPersonUpdateOne) check() error {
	if v, ok := npuo.mutation.Name(); ok {
		if err := naturalperson.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "NaturalPerson.name": %w`, err)}
		}
	}
	if v, ok := npuo.mutation.GetType(); ok {
		if err := naturalperson.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "NaturalPerson.type": %w`, err)}
		}
	}
	if v, ok := npuo.mutation.Password(); ok {
		if err := naturalperson.PasswordValidator(v); err != nil {
			return &ValidationError{Name: "password", err: fmt.Errorf(`ent: validator failed for field "NaturalPerson.password": %w`, err)}
		}
	}
	return nil
}

func (npuo *NaturalPersonUpdateOne) sqlSave(ctx context.Context) (_node *NaturalPerson, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   naturalperson.Table,
			Columns: naturalperson.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: naturalperson.FieldID,
			},
		},
	}
	id, ok := npuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "NaturalPerson.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := npuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, naturalperson.FieldID)
		for _, f := range fields {
			if !naturalperson.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != naturalperson.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := npuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := npuo.mutation.Name(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: naturalperson.FieldName,
		})
	}
	if value, ok := npuo.mutation.Displayname(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: naturalperson.FieldDisplayname,
		})
	}
	if npuo.mutation.DisplaynameCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Column: naturalperson.FieldDisplayname,
		})
	}
	if value, ok := npuo.mutation.GetType(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: naturalperson.FieldType,
		})
	}
	if value, ok := npuo.mutation.Password(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: naturalperson.FieldPassword,
		})
	}
	if value, ok := npuo.mutation.UpdatedAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: naturalperson.FieldUpdatedAt,
		})
	}
	if npuo.mutation.KeysCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.KeysTable,
			Columns: []string{naturalperson.KeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: privatekey.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npuo.mutation.RemovedKeysIDs(); len(nodes) > 0 && !npuo.mutation.KeysCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.KeysTable,
			Columns: []string{naturalperson.KeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: privatekey.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npuo.mutation.KeysIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.KeysTable,
			Columns: []string{naturalperson.KeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: privatekey.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if npuo.mutation.CredentialsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.CredentialsTable,
			Columns: []string{naturalperson.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: credential.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npuo.mutation.RemovedCredentialsIDs(); len(nodes) > 0 && !npuo.mutation.CredentialsCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.CredentialsTable,
			Columns: []string{naturalperson.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: credential.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := npuo.mutation.CredentialsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   naturalperson.CredentialsTable,
			Columns: []string{naturalperson.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: credential.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &NaturalPerson{config: npuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, npuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{naturalperson.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
