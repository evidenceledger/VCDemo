// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/hesusruiz/vcbackend/ent/did"
	"github.com/hesusruiz/vcbackend/ent/user"
)

// DIDCreate is the builder for creating a DID entity.
type DIDCreate struct {
	config
	mutation *DIDMutation
	hooks    []Hook
}

// SetPrivatekey sets the "privatekey" field.
func (dc *DIDCreate) SetPrivatekey(b []byte) *DIDCreate {
	dc.mutation.SetPrivatekey(b)
	return dc
}

// SetMethod sets the "method" field.
func (dc *DIDCreate) SetMethod(s string) *DIDCreate {
	dc.mutation.SetMethod(s)
	return dc
}

// SetNillableMethod sets the "method" field if the given value is not nil.
func (dc *DIDCreate) SetNillableMethod(s *string) *DIDCreate {
	if s != nil {
		dc.SetMethod(*s)
	}
	return dc
}

// SetCreatedAt sets the "created_at" field.
func (dc *DIDCreate) SetCreatedAt(t time.Time) *DIDCreate {
	dc.mutation.SetCreatedAt(t)
	return dc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (dc *DIDCreate) SetNillableCreatedAt(t *time.Time) *DIDCreate {
	if t != nil {
		dc.SetCreatedAt(*t)
	}
	return dc
}

// SetUpdatedAt sets the "updated_at" field.
func (dc *DIDCreate) SetUpdatedAt(t time.Time) *DIDCreate {
	dc.mutation.SetUpdatedAt(t)
	return dc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (dc *DIDCreate) SetNillableUpdatedAt(t *time.Time) *DIDCreate {
	if t != nil {
		dc.SetUpdatedAt(*t)
	}
	return dc
}

// SetID sets the "id" field.
func (dc *DIDCreate) SetID(s string) *DIDCreate {
	dc.mutation.SetID(s)
	return dc
}

// SetUserID sets the "user" edge to the User entity by ID.
func (dc *DIDCreate) SetUserID(id string) *DIDCreate {
	dc.mutation.SetUserID(id)
	return dc
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (dc *DIDCreate) SetNillableUserID(id *string) *DIDCreate {
	if id != nil {
		dc = dc.SetUserID(*id)
	}
	return dc
}

// SetUser sets the "user" edge to the User entity.
func (dc *DIDCreate) SetUser(u *User) *DIDCreate {
	return dc.SetUserID(u.ID)
}

// Mutation returns the DIDMutation object of the builder.
func (dc *DIDCreate) Mutation() *DIDMutation {
	return dc.mutation
}

// Save creates the DID in the database.
func (dc *DIDCreate) Save(ctx context.Context) (*DID, error) {
	var (
		err  error
		node *DID
	)
	dc.defaults()
	if len(dc.hooks) == 0 {
		if err = dc.check(); err != nil {
			return nil, err
		}
		node, err = dc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DIDMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = dc.check(); err != nil {
				return nil, err
			}
			dc.mutation = mutation
			if node, err = dc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(dc.hooks) - 1; i >= 0; i-- {
			if dc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = dc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, dc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*DID)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from DIDMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (dc *DIDCreate) SaveX(ctx context.Context) *DID {
	v, err := dc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dc *DIDCreate) Exec(ctx context.Context) error {
	_, err := dc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dc *DIDCreate) ExecX(ctx context.Context) {
	if err := dc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (dc *DIDCreate) defaults() {
	if _, ok := dc.mutation.CreatedAt(); !ok {
		v := did.DefaultCreatedAt()
		dc.mutation.SetCreatedAt(v)
	}
	if _, ok := dc.mutation.UpdatedAt(); !ok {
		v := did.DefaultUpdatedAt()
		dc.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dc *DIDCreate) check() error {
	if _, ok := dc.mutation.Privatekey(); !ok {
		return &ValidationError{Name: "privatekey", err: errors.New(`ent: missing required field "DID.privatekey"`)}
	}
	if _, ok := dc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "DID.created_at"`)}
	}
	if _, ok := dc.mutation.UpdatedAt(); !ok {
		return &ValidationError{Name: "updated_at", err: errors.New(`ent: missing required field "DID.updated_at"`)}
	}
	return nil
}

func (dc *DIDCreate) sqlSave(ctx context.Context) (*DID, error) {
	_node, _spec := dc.createSpec()
	if err := sqlgraph.CreateNode(ctx, dc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected DID.ID type: %T", _spec.ID.Value)
		}
	}
	return _node, nil
}

func (dc *DIDCreate) createSpec() (*DID, *sqlgraph.CreateSpec) {
	var (
		_node = &DID{config: dc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: did.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: did.FieldID,
			},
		}
	)
	if id, ok := dc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := dc.mutation.Privatekey(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: did.FieldPrivatekey,
		})
		_node.Privatekey = value
	}
	if value, ok := dc.mutation.Method(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: did.FieldMethod,
		})
		_node.Method = value
	}
	if value, ok := dc.mutation.CreatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: did.FieldCreatedAt,
		})
		_node.CreatedAt = value
	}
	if value, ok := dc.mutation.UpdatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: did.FieldUpdatedAt,
		})
		_node.UpdatedAt = value
	}
	if nodes := dc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   did.UserTable,
			Columns: []string{did.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeString,
					Column: user.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_dids = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// DIDCreateBulk is the builder for creating many DID entities in bulk.
type DIDCreateBulk struct {
	config
	builders []*DIDCreate
}

// Save creates the DID entities in the database.
func (dcb *DIDCreateBulk) Save(ctx context.Context) ([]*DID, error) {
	specs := make([]*sqlgraph.CreateSpec, len(dcb.builders))
	nodes := make([]*DID, len(dcb.builders))
	mutators := make([]Mutator, len(dcb.builders))
	for i := range dcb.builders {
		func(i int, root context.Context) {
			builder := dcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DIDMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, dcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, dcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, dcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (dcb *DIDCreateBulk) SaveX(ctx context.Context) []*DID {
	v, err := dcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dcb *DIDCreateBulk) Exec(ctx context.Context) error {
	_, err := dcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dcb *DIDCreateBulk) ExecX(ctx context.Context) {
	if err := dcb.Exec(ctx); err != nil {
		panic(err)
	}
}
