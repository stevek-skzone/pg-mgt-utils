## PgRole class

The `PgRole` class provides methods for creating, dropping, and altering PostgreSQL roles. It takes a `conn` argument in its constructor, which is a connection object to a PostgreSQL database.

### create_user method

Creates a new PostgreSQL role with the specified `rolename` and `password`. It also takes optional arguments for `options`, `max_connections`, and `expiry`, which are used to set additional role attributes.

### drop_role method

Drops an existing PostgreSQL role with the specified `rolename`.

### add_users_to_role method

Adds one or more PostgreSQL users with the specified `usernames` to an existing PostgreSQL role with the specified `rolename`.

### remove_users_from_role method

Removes one or more PostgreSQL users with the specified `usernames` from an existing PostgreSQL role with the specified `rolename`.

### grant_database_permissions_to_role method

Grants the specified `permissions` on the specified `database` to the PostgreSQL role with the specified `rolename`.

### revoke_database_permissions_from_role method

Revokes the specified `permissions` on the specified `database` from the PostgreSQL role with the specified `rolename`.

### grant_default_permissions_to_role method

Grants the specified `permissions` on the specified `schema` to the PostgreSQL role with the specified `rolename`.

### revoke_default_permissions_from_role method

Revokes the specified `permissions` on the specified `schema` from the PostgreSQL role with the specified `rolename`.

### check_role_exists method

Checks if a PostgreSQL role with the specified `rolename` exists.

### return_role_info method

Returns information about a PostgreSQL role with the specified `rolename`.

### _parse_role_attrs function

Parses role attributes specified as a string and returns them as a space-separated string.