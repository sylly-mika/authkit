package authkit

import "github.com/sylly-mika/authkit/db"

// Q returns q with authkit's table names qualified by Config.Schema; q itself when Schema is "".
func (c *Core) Q(q db.Querier) db.Querier { return c.s.names.Q(q) }
