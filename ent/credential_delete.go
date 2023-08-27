// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/hesusruiz/vcbackend/ent/credential"
	"github.com/hesusruiz/vcbackend/ent/predicate"
)

// CredentialDelete is the builder for deleting a Credential entity.
type CredentialDelete struct {
	config
	hooks    []Hook
	mutation *CredentialMutation
}

// Where appends a list predicates to the CredentialDelete builder.
func (cd *CredentialDelete) Where(ps ...predicate.Credential) *CredentialDelete {
	cd.mutation.Where(ps...)
	return cd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (cd *CredentialDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(cd.hooks) == 0 {
		affected, err = cd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*CredentialMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			cd.mutation = mutation
			affected, err = cd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(cd.hooks) - 1; i >= 0; i-- {
			if cd.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = cd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, cd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (cd *CredentialDelete) ExecX(ctx context.Context) int {
	n, err := cd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (cd *CredentialDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: credential.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: credential.FieldID,
			},
		},
	}
	if ps := cd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, cd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	return affected, err
}

// CredentialDeleteOne is the builder for deleting a single Credential entity.
type CredentialDeleteOne struct {
	cd *CredentialDelete
}

// Exec executes the deletion query.
func (cdo *CredentialDeleteOne) Exec(ctx context.Context) error {
	n, err := cdo.cd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{credential.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (cdo *CredentialDeleteOne) ExecX(ctx context.Context) {
	cdo.cd.ExecX(ctx)
}
