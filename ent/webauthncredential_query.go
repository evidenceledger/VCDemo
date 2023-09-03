// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/hesusruiz/vcbackend/ent/predicate"
	"github.com/hesusruiz/vcbackend/ent/user"
	"github.com/hesusruiz/vcbackend/ent/webauthncredential"
)

// WebauthnCredentialQuery is the builder for querying WebauthnCredential entities.
type WebauthnCredentialQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.WebauthnCredential
	// eager-loading edges.
	withUser *UserQuery
	withFKs  bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the WebauthnCredentialQuery builder.
func (wcq *WebauthnCredentialQuery) Where(ps ...predicate.WebauthnCredential) *WebauthnCredentialQuery {
	wcq.predicates = append(wcq.predicates, ps...)
	return wcq
}

// Limit adds a limit step to the query.
func (wcq *WebauthnCredentialQuery) Limit(limit int) *WebauthnCredentialQuery {
	wcq.limit = &limit
	return wcq
}

// Offset adds an offset step to the query.
func (wcq *WebauthnCredentialQuery) Offset(offset int) *WebauthnCredentialQuery {
	wcq.offset = &offset
	return wcq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (wcq *WebauthnCredentialQuery) Unique(unique bool) *WebauthnCredentialQuery {
	wcq.unique = &unique
	return wcq
}

// Order adds an order step to the query.
func (wcq *WebauthnCredentialQuery) Order(o ...OrderFunc) *WebauthnCredentialQuery {
	wcq.order = append(wcq.order, o...)
	return wcq
}

// QueryUser chains the current query on the "user" edge.
func (wcq *WebauthnCredentialQuery) QueryUser() *UserQuery {
	query := &UserQuery{config: wcq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := wcq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := wcq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(webauthncredential.Table, webauthncredential.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, webauthncredential.UserTable, webauthncredential.UserColumn),
		)
		fromU = sqlgraph.SetNeighbors(wcq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first WebauthnCredential entity from the query.
// Returns a *NotFoundError when no WebauthnCredential was found.
func (wcq *WebauthnCredentialQuery) First(ctx context.Context) (*WebauthnCredential, error) {
	nodes, err := wcq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{webauthncredential.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) FirstX(ctx context.Context) *WebauthnCredential {
	node, err := wcq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first WebauthnCredential ID from the query.
// Returns a *NotFoundError when no WebauthnCredential ID was found.
func (wcq *WebauthnCredentialQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = wcq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{webauthncredential.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) FirstIDX(ctx context.Context) string {
	id, err := wcq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single WebauthnCredential entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one WebauthnCredential entity is found.
// Returns a *NotFoundError when no WebauthnCredential entities are found.
func (wcq *WebauthnCredentialQuery) Only(ctx context.Context) (*WebauthnCredential, error) {
	nodes, err := wcq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{webauthncredential.Label}
	default:
		return nil, &NotSingularError{webauthncredential.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) OnlyX(ctx context.Context) *WebauthnCredential {
	node, err := wcq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only WebauthnCredential ID in the query.
// Returns a *NotSingularError when more than one WebauthnCredential ID is found.
// Returns a *NotFoundError when no entities are found.
func (wcq *WebauthnCredentialQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = wcq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{webauthncredential.Label}
	default:
		err = &NotSingularError{webauthncredential.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) OnlyIDX(ctx context.Context) string {
	id, err := wcq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of WebauthnCredentials.
func (wcq *WebauthnCredentialQuery) All(ctx context.Context) ([]*WebauthnCredential, error) {
	if err := wcq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return wcq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) AllX(ctx context.Context) []*WebauthnCredential {
	nodes, err := wcq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of WebauthnCredential IDs.
func (wcq *WebauthnCredentialQuery) IDs(ctx context.Context) ([]string, error) {
	var ids []string
	if err := wcq.Select(webauthncredential.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) IDsX(ctx context.Context) []string {
	ids, err := wcq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (wcq *WebauthnCredentialQuery) Count(ctx context.Context) (int, error) {
	if err := wcq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return wcq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) CountX(ctx context.Context) int {
	count, err := wcq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (wcq *WebauthnCredentialQuery) Exist(ctx context.Context) (bool, error) {
	if err := wcq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return wcq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (wcq *WebauthnCredentialQuery) ExistX(ctx context.Context) bool {
	exist, err := wcq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the WebauthnCredentialQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (wcq *WebauthnCredentialQuery) Clone() *WebauthnCredentialQuery {
	if wcq == nil {
		return nil
	}
	return &WebauthnCredentialQuery{
		config:     wcq.config,
		limit:      wcq.limit,
		offset:     wcq.offset,
		order:      append([]OrderFunc{}, wcq.order...),
		predicates: append([]predicate.WebauthnCredential{}, wcq.predicates...),
		withUser:   wcq.withUser.Clone(),
		// clone intermediate query.
		sql:    wcq.sql.Clone(),
		path:   wcq.path,
		unique: wcq.unique,
	}
}

// WithUser tells the query-builder to eager-load the nodes that are connected to
// the "user" edge. The optional arguments are used to configure the query builder of the edge.
func (wcq *WebauthnCredentialQuery) WithUser(opts ...func(*UserQuery)) *WebauthnCredentialQuery {
	query := &UserQuery{config: wcq.config}
	for _, opt := range opts {
		opt(query)
	}
	wcq.withUser = query
	return wcq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreateTime time.Time `json:"create_time,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.WebauthnCredential.Query().
//		GroupBy(webauthncredential.FieldCreateTime).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (wcq *WebauthnCredentialQuery) GroupBy(field string, fields ...string) *WebauthnCredentialGroupBy {
	grbuild := &WebauthnCredentialGroupBy{config: wcq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := wcq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return wcq.sqlQuery(ctx), nil
	}
	grbuild.label = webauthncredential.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreateTime time.Time `json:"create_time,omitempty"`
//	}
//
//	client.WebauthnCredential.Query().
//		Select(webauthncredential.FieldCreateTime).
//		Scan(ctx, &v)
func (wcq *WebauthnCredentialQuery) Select(fields ...string) *WebauthnCredentialSelect {
	wcq.fields = append(wcq.fields, fields...)
	selbuild := &WebauthnCredentialSelect{WebauthnCredentialQuery: wcq}
	selbuild.label = webauthncredential.Label
	selbuild.flds, selbuild.scan = &wcq.fields, selbuild.Scan
	return selbuild
}

func (wcq *WebauthnCredentialQuery) prepareQuery(ctx context.Context) error {
	for _, f := range wcq.fields {
		if !webauthncredential.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if wcq.path != nil {
		prev, err := wcq.path(ctx)
		if err != nil {
			return err
		}
		wcq.sql = prev
	}
	return nil
}

func (wcq *WebauthnCredentialQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*WebauthnCredential, error) {
	var (
		nodes       = []*WebauthnCredential{}
		withFKs     = wcq.withFKs
		_spec       = wcq.querySpec()
		loadedTypes = [1]bool{
			wcq.withUser != nil,
		}
	)
	if wcq.withUser != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, webauthncredential.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*WebauthnCredential).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &WebauthnCredential{config: wcq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, wcq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}

	if query := wcq.withUser; query != nil {
		ids := make([]string, 0, len(nodes))
		nodeids := make(map[string][]*WebauthnCredential)
		for i := range nodes {
			if nodes[i].user_authncredentials == nil {
				continue
			}
			fk := *nodes[i].user_authncredentials
			if _, ok := nodeids[fk]; !ok {
				ids = append(ids, fk)
			}
			nodeids[fk] = append(nodeids[fk], nodes[i])
		}
		query.Where(user.IDIn(ids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := nodeids[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "user_authncredentials" returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.User = n
			}
		}
	}

	return nodes, nil
}

func (wcq *WebauthnCredentialQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := wcq.querySpec()
	_spec.Node.Columns = wcq.fields
	if len(wcq.fields) > 0 {
		_spec.Unique = wcq.unique != nil && *wcq.unique
	}
	return sqlgraph.CountNodes(ctx, wcq.driver, _spec)
}

func (wcq *WebauthnCredentialQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := wcq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (wcq *WebauthnCredentialQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   webauthncredential.Table,
			Columns: webauthncredential.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: webauthncredential.FieldID,
			},
		},
		From:   wcq.sql,
		Unique: true,
	}
	if unique := wcq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := wcq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, webauthncredential.FieldID)
		for i := range fields {
			if fields[i] != webauthncredential.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := wcq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := wcq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := wcq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := wcq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (wcq *WebauthnCredentialQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(wcq.driver.Dialect())
	t1 := builder.Table(webauthncredential.Table)
	columns := wcq.fields
	if len(columns) == 0 {
		columns = webauthncredential.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if wcq.sql != nil {
		selector = wcq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if wcq.unique != nil && *wcq.unique {
		selector.Distinct()
	}
	for _, p := range wcq.predicates {
		p(selector)
	}
	for _, p := range wcq.order {
		p(selector)
	}
	if offset := wcq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := wcq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// WebauthnCredentialGroupBy is the group-by builder for WebauthnCredential entities.
type WebauthnCredentialGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (wcgb *WebauthnCredentialGroupBy) Aggregate(fns ...AggregateFunc) *WebauthnCredentialGroupBy {
	wcgb.fns = append(wcgb.fns, fns...)
	return wcgb
}

// Scan applies the group-by query and scans the result into the given value.
func (wcgb *WebauthnCredentialGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := wcgb.path(ctx)
	if err != nil {
		return err
	}
	wcgb.sql = query
	return wcgb.sqlScan(ctx, v)
}

func (wcgb *WebauthnCredentialGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range wcgb.fields {
		if !webauthncredential.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := wcgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := wcgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (wcgb *WebauthnCredentialGroupBy) sqlQuery() *sql.Selector {
	selector := wcgb.sql.Select()
	aggregation := make([]string, 0, len(wcgb.fns))
	for _, fn := range wcgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(wcgb.fields)+len(wcgb.fns))
		for _, f := range wcgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(wcgb.fields...)...)
}

// WebauthnCredentialSelect is the builder for selecting fields of WebauthnCredential entities.
type WebauthnCredentialSelect struct {
	*WebauthnCredentialQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (wcs *WebauthnCredentialSelect) Scan(ctx context.Context, v interface{}) error {
	if err := wcs.prepareQuery(ctx); err != nil {
		return err
	}
	wcs.sql = wcs.WebauthnCredentialQuery.sqlQuery(ctx)
	return wcs.sqlScan(ctx, v)
}

func (wcs *WebauthnCredentialSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := wcs.sql.Query()
	if err := wcs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
