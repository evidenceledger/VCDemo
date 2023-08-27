// Code generated by ent, DO NOT EDIT.

package privatekey

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/hesusruiz/vcbackend/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// Kty applies equality check predicate on the "kty" field. It's identical to KtyEQ.
func Kty(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldKty), v))
	})
}

// Alg applies equality check predicate on the "alg" field. It's identical to AlgEQ.
func Alg(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldAlg), v))
	})
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCreatedAt), v))
	})
}

// UpdatedAt applies equality check predicate on the "updated_at" field. It's identical to UpdatedAtEQ.
func UpdatedAt(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldUpdatedAt), v))
	})
}

// KtyEQ applies the EQ predicate on the "kty" field.
func KtyEQ(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldKty), v))
	})
}

// KtyNEQ applies the NEQ predicate on the "kty" field.
func KtyNEQ(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldKty), v))
	})
}

// KtyIn applies the In predicate on the "kty" field.
func KtyIn(vs ...string) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldKty), v...))
	})
}

// KtyNotIn applies the NotIn predicate on the "kty" field.
func KtyNotIn(vs ...string) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldKty), v...))
	})
}

// KtyGT applies the GT predicate on the "kty" field.
func KtyGT(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldKty), v))
	})
}

// KtyGTE applies the GTE predicate on the "kty" field.
func KtyGTE(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldKty), v))
	})
}

// KtyLT applies the LT predicate on the "kty" field.
func KtyLT(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldKty), v))
	})
}

// KtyLTE applies the LTE predicate on the "kty" field.
func KtyLTE(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldKty), v))
	})
}

// KtyContains applies the Contains predicate on the "kty" field.
func KtyContains(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldKty), v))
	})
}

// KtyHasPrefix applies the HasPrefix predicate on the "kty" field.
func KtyHasPrefix(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldKty), v))
	})
}

// KtyHasSuffix applies the HasSuffix predicate on the "kty" field.
func KtyHasSuffix(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldKty), v))
	})
}

// KtyEqualFold applies the EqualFold predicate on the "kty" field.
func KtyEqualFold(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldKty), v))
	})
}

// KtyContainsFold applies the ContainsFold predicate on the "kty" field.
func KtyContainsFold(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldKty), v))
	})
}

// AlgEQ applies the EQ predicate on the "alg" field.
func AlgEQ(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldAlg), v))
	})
}

// AlgNEQ applies the NEQ predicate on the "alg" field.
func AlgNEQ(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldAlg), v))
	})
}

// AlgIn applies the In predicate on the "alg" field.
func AlgIn(vs ...string) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldAlg), v...))
	})
}

// AlgNotIn applies the NotIn predicate on the "alg" field.
func AlgNotIn(vs ...string) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldAlg), v...))
	})
}

// AlgGT applies the GT predicate on the "alg" field.
func AlgGT(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldAlg), v))
	})
}

// AlgGTE applies the GTE predicate on the "alg" field.
func AlgGTE(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldAlg), v))
	})
}

// AlgLT applies the LT predicate on the "alg" field.
func AlgLT(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldAlg), v))
	})
}

// AlgLTE applies the LTE predicate on the "alg" field.
func AlgLTE(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldAlg), v))
	})
}

// AlgContains applies the Contains predicate on the "alg" field.
func AlgContains(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldAlg), v))
	})
}

// AlgHasPrefix applies the HasPrefix predicate on the "alg" field.
func AlgHasPrefix(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldAlg), v))
	})
}

// AlgHasSuffix applies the HasSuffix predicate on the "alg" field.
func AlgHasSuffix(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldAlg), v))
	})
}

// AlgIsNil applies the IsNil predicate on the "alg" field.
func AlgIsNil() predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.IsNull(s.C(FieldAlg)))
	})
}

// AlgNotNil applies the NotNil predicate on the "alg" field.
func AlgNotNil() predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.NotNull(s.C(FieldAlg)))
	})
}

// AlgEqualFold applies the EqualFold predicate on the "alg" field.
func AlgEqualFold(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldAlg), v))
	})
}

// AlgContainsFold applies the ContainsFold predicate on the "alg" field.
func AlgContainsFold(v string) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldAlg), v))
	})
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldCreatedAt), v...))
	})
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldCreatedAt), v...))
	})
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldCreatedAt), v))
	})
}

// UpdatedAtEQ applies the EQ predicate on the "updated_at" field.
func UpdatedAtEQ(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldUpdatedAt), v))
	})
}

// UpdatedAtNEQ applies the NEQ predicate on the "updated_at" field.
func UpdatedAtNEQ(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldUpdatedAt), v))
	})
}

// UpdatedAtIn applies the In predicate on the "updated_at" field.
func UpdatedAtIn(vs ...time.Time) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldUpdatedAt), v...))
	})
}

// UpdatedAtNotIn applies the NotIn predicate on the "updated_at" field.
func UpdatedAtNotIn(vs ...time.Time) predicate.PrivateKey {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PrivateKey(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldUpdatedAt), v...))
	})
}

// UpdatedAtGT applies the GT predicate on the "updated_at" field.
func UpdatedAtGT(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldUpdatedAt), v))
	})
}

// UpdatedAtGTE applies the GTE predicate on the "updated_at" field.
func UpdatedAtGTE(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldUpdatedAt), v))
	})
}

// UpdatedAtLT applies the LT predicate on the "updated_at" field.
func UpdatedAtLT(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldUpdatedAt), v))
	})
}

// UpdatedAtLTE applies the LTE predicate on the "updated_at" field.
func UpdatedAtLTE(v time.Time) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldUpdatedAt), v))
	})
}

// HasUser applies the HasEdge predicate on the "user" edge.
func HasUser() predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(UserTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasUserWith applies the HasEdge predicate on the "user" edge with a given conditions (other predicates).
func HasUserWith(preds ...predicate.User) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(UserInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.PrivateKey) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.PrivateKey) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.PrivateKey) predicate.PrivateKey {
	return predicate.PrivateKey(func(s *sql.Selector) {
		p(s.Not())
	})
}
