
import itertools
import re
import traceback
from hashlib import md5, sha256, pbkdf2_hmac
import hmac
from base64 import b64decode
import psycopg2
from psycopg2.extras import DictCursor
from typing import Any, Tuple, Dict, List, Optional, Union
from passlib.utils import saslprep


FLAGS = ('SUPERUSER', 'CREATEROLE', 'CREATEDB', 'INHERIT', 'LOGIN', 'REPLICATION')
FLAGS_BY_VERSION = {'BYPASSRLS': 90500}

SCRAM_SHA256_REGEX = r'^SCRAM-SHA-256\$(\d+):([A-Za-z0-9+\/=]+)\$([A-Za-z0-9+\/=]+):([A-Za-z0-9+\/=]+)$'

# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
VALID_PRIVS = dict(table=frozenset(('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'ALL')),
                   database=frozenset(
                       ('CREATE', 'CONNECT', 'TEMPORARY', 'TEMP', 'ALL')),
                   )

# map to cope with idiosyncrasies of SUPERUSER and LOGIN
PRIV_TO_AUTHID_COLUMN = dict(SUPERUSER='rolsuper', CREATEROLE='rolcreaterole',
                             CREATEDB='rolcreatedb', INHERIT='rolinherit', LOGIN='rolcanlogin',
                             REPLICATION='rolreplication', BYPASSRLS='rolbypassrls')

executed_queries = []

# This is a special list for debugging.
# If you need to fetch information (e.g. results of cursor.fetchall(),
# queries built with cursor.mogrify(), vars values, etc.):
# 1. Put debug_info.append(<information_you_need>) as many times as you need.
# 2. Run integration tests or you playbook with -vvv
# 3. If it's not empty, you'll see the list in the returned json.
debug_info = []


class InvalidFlagsError(Exception):
    pass


class InvalidPrivsError(Exception):
    pass



def user_exists(cursor: Any, user: str) -> bool:
    # The PUBLIC user is a special case that is always there
    if user == 'PUBLIC':
        return True
    query = "SELECT rolname FROM pg_roles WHERE rolname=%(user)s"
    cursor.execute(query, {'user': user})
    return cursor.rowcount > 0


def user_add(cursor: Any, user: str, password: Optional[str], role_attr_flags: str, encrypted: str, expires: Optional[str], conn_limit: Optional[int]) -> bool:
    """Create a new database user (role)."""
    query_password_data: Dict[str, Optional[str]] = {'password': password, 'expires': expires}
    query = [f'CREATE USER "{user}"']
    if password:
        query.append(f"WITH {encrypted}")
        query.append("PASSWORD %(password)s")
    if expires:
        query.append("VALID UNTIL %(expires)s")
    if conn_limit:
        query.append(f"CONNECTION LIMIT {conn_limit}")
    query.append(role_attr_flags)
    query = ' '.join(query)
    executed_queries.append(query)
    cursor.execute(query, query_password_data)
    return True



def user_should_we_change_password(current_role_attrs: Optional[Dict[str, Any]], user: str, password: Optional[str], encrypted: str) -> bool:
    """Check if we should change the user's password.

    Compare the proposed password with the existing one, comparing
    hashes if encrypted. If we can't access it assume yes.
    """

    if current_role_attrs is None:
        # on some databases, E.g. AWS RDS instances, there is no access to
        # the pg_authid relation to check the pre-existing password, so we
        # just assume password is different
        return True

    # Do we actually need to do anything?
    pwchanging = False
    if password is not None:
        # Empty password means that the role shouldn't have a password, which
        # means we need to check if the current password is None.
        if password == '':
            if current_role_attrs['rolpassword'] is not None:
                pwchanging = True
        # If the provided password is a SCRAM hash, compare it directly to the current password
        elif re.match(SCRAM_SHA256_REGEX, password):
            if password != current_role_attrs['rolpassword']:
                pwchanging = True

        # SCRAM hashes are represented as a special object, containing hash data:
        # `SCRAM-SHA-256$<iteration count>:<salt>$<StoredKey>:<ServerKey>`
        # for reference, see https://www.postgresql.org/docs/current/catalog-pg-authid.html
        elif current_role_attrs['rolpassword'] is not None \
                and re.match(SCRAM_SHA256_REGEX, current_role_attrs['rolpassword']):

            r = re.match(SCRAM_SHA256_REGEX, current_role_attrs['rolpassword'])
            try:
                # extract SCRAM params from rolpassword
                it = int(r.group(1))
                salt = b64decode(r.group(2))
                server_key = b64decode(r.group(4))
                # we'll never need `storedKey` as it is only used for server auth in SCRAM
                # storedKey = b64decode(r.group(3))

                # from RFC5802 https://tools.ietf.org/html/rfc5802#section-3
                # SaltedPassword  := Hi(Normalize(password), salt, i)
                # ServerKey       := HMAC(SaltedPassword, "Server Key")
                normalized_password = saslprep.saslprep(str(password))
                salted_password = pbkdf2_hmac('sha256', bytes(normalized_password), salt, it)

                server_key_verifier = hmac.new(salted_password, digestmod=sha256)
                server_key_verifier.update(b'Server Key')

                if server_key_verifier.digest() != server_key:
                    pwchanging = True
            except Exception:
                # We assume the password is not scram encrypted
                # or we cannot check it properly, e.g. due to missing dependencies
                pwchanging = True

        # 32: MD5 hashes are represented as a sequence of 32 hexadecimal digits
        #  3: The size of the 'md5' prefix
        # When the provided password looks like a MD5-hash, value of
        # 'encrypted' is ignored.
        elif (password.startswith('md5') and len(password) == 32 + 3) or encrypted == 'UNENCRYPTED':
            if password != current_role_attrs['rolpassword']:
                pwchanging = True
        elif encrypted == 'ENCRYPTED':
            hashed_password = 'md5{0}'.format(md5(f"{password}{user}".encode()).hexdigest())
            if hashed_password != current_role_attrs['rolpassword']:
                pwchanging = True

    return pwchanging


def user_alter(db_connection, module, user: str, password: Optional[str], role_attr_flags: str, encrypted: str, expires: Optional[str], no_password_changes: bool, conn_limit: Optional[int]) -> bool:
    """Change user password and/or attributes. Return True if changed, False otherwise."""    """Change user password and/or attributes. Return True if changed, False otherwise."""
    changed = False

    cursor = db_connection.cursor(cursor_factory=DictCursor)
    # Note: role_attr_flags escaped by parse_role_attrs and encrypted is a
    # literal
    if user == 'PUBLIC':
        if password is not None:
            print("cannot change the password for PUBLIC user")
        elif role_attr_flags != '':
            print("cannot change the role_attr_flags for PUBLIC user")
        else:
            return False

    # Handle passwords.
    if not no_password_changes and (password is not None or role_attr_flags != '' or expires is not None or conn_limit is not None):
        # Select password and all flag-like columns in order to verify changes.
        try:
            select = "SELECT * FROM pg_authid where rolname=%(user)s"
            cursor.execute(select, {"user": user})
            # Grab current role attributes.
            current_role_attrs = cursor.fetchone()
        except psycopg2.ProgrammingError:
            current_role_attrs = None
            db_connection.rollback()

        pwchanging = user_should_we_change_password(current_role_attrs, user, password, encrypted)

        if current_role_attrs is None:
            try:
                # AWS RDS instances does not allow user to access pg_authid
                # so try to get current_role_attrs from pg_roles tables
                select = "SELECT * FROM pg_roles where rolname=%(user)s"
                cursor.execute(select, {"user": user})
                # Grab current role attributes from pg_roles
                current_role_attrs = cursor.fetchone()
            except psycopg2.ProgrammingError as e:
                db_connection.rollback()
                module.fail_json(msg="Failed to get role details for current user %s: %s" % (user, e))

        role_attr_flags_changing = False
        if role_attr_flags:
            role_attr_flags_dict = {}
            for r in role_attr_flags.split(' '):
                if r.startswith('NO'):
                    role_attr_flags_dict[r.replace('NO', '', 1)] = False
                else:
                    role_attr_flags_dict[r] = True

            for role_attr_name, role_attr_value in role_attr_flags_dict.items():
                if current_role_attrs[PRIV_TO_AUTHID_COLUMN[role_attr_name]] != role_attr_value:
                    role_attr_flags_changing = True

        if expires is not None:
            cursor.execute("SELECT %s::timestamptz;", (expires,))
            expires_with_tz = cursor.fetchone()[0]
            expires_changing = expires_with_tz != current_role_attrs.get('rolvaliduntil')
        else:
            expires_changing = False

        conn_limit_changing = (conn_limit is not None and conn_limit != current_role_attrs['rolconnlimit'])

        if not pwchanging and not role_attr_flags_changing and not expires_changing and not conn_limit_changing:
            return False

        alter = ['ALTER USER "%(user)s"' % {"user": user}]
        if pwchanging:
            if password != '':
                alter.append("WITH %(crypt)s" % {"crypt": encrypted})
                alter.append("PASSWORD %(password)s")
            else:
                alter.append("WITH PASSWORD NULL")
            alter.append(role_attr_flags)
        elif role_attr_flags:
            alter.append('WITH %s' % role_attr_flags)
        if expires is not None:
            alter.append("VALID UNTIL %(expires)s")
        if conn_limit is not None:
            alter.append("CONNECTION LIMIT %(conn_limit)s" % {"conn_limit": conn_limit})

        query_password_data = dict(password=password, expires=expires)
        try:
            statement = ' '.join(alter)
            cursor.execute(statement, query_password_data)
            changed = True
            executed_queries.append(statement)
        except psycopg2.InternalError as e:
            if e.pgcode == '25006':
                # Handle errors due to read-only transactions indicated by pgcode 25006
                # ERROR:  cannot execute ALTER ROLE in a read-only transaction
                changed = False
                module.fail_json(msg=e.pgerror, exception=traceback.format_exc())
                return changed
            else:
                raise psycopg2.InternalError(e)
        except psycopg2.NotSupportedError as e:
            module.fail_json(msg=e.pgerror, exception=traceback.format_exc())

    elif no_password_changes and role_attr_flags != '':
        # Grab role information from pg_roles instead of pg_authid
        select = "SELECT * FROM pg_roles where rolname=%(user)s"
        cursor.execute(select, {"user": user})
        # Grab current role attributes.
        current_role_attrs = cursor.fetchone()

        role_attr_flags_changing = False

        if role_attr_flags:
            role_attr_flags_dict = {}
            for r in role_attr_flags.split(' '):
                if r.startswith('NO'):
                    role_attr_flags_dict[r.replace('NO', '', 1)] = False
                else:
                    role_attr_flags_dict[r] = True

            for role_attr_name, role_attr_value in role_attr_flags_dict.items():
                if current_role_attrs[PRIV_TO_AUTHID_COLUMN[role_attr_name]] != role_attr_value:
                    role_attr_flags_changing = True

        if not role_attr_flags_changing:
            return False

        alter = ['ALTER USER "%(user)s"' %
                 {"user": user}]
        if role_attr_flags:
            alter.append('WITH %s' % role_attr_flags)

        try:
            statement = ' '.join(alter)
            cursor.execute(statement)
            executed_queries.append(statement)
        except psycopg2.InternalError as e:
            if e.pgcode == '25006':
                # Handle errors due to read-only transactions indicated by pgcode 25006
                # ERROR:  cannot execute ALTER ROLE in a read-only transaction
                changed = False
                module.fail_json(msg=e.pgerror, exception=traceback.format_exc())
                return changed
            else:
                raise psycopg2.InternalError(e)

        # Grab new role attributes.
        cursor.execute(select, {"user": user})
        new_role_attrs = cursor.fetchone()

        # Detect any differences between current_ and new_role_attrs.
        changed = current_role_attrs != new_role_attrs

    return changed


def user_delete(cursor, user):
    """Try to remove a user. Returns True if successful otherwise False"""
    cursor.execute("SAVEPOINT ansible_pgsql_user_delete")
    try:
        query = 'DROP USER "%s"' % user
        executed_queries.append(query)
        cursor.execute(query)
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT ansible_pgsql_user_delete")
        cursor.execute("RELEASE SAVEPOINT ansible_pgsql_user_delete")
        return False

    cursor.execute("RELEASE SAVEPOINT ansible_pgsql_user_delete")
    return True





# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
def get_database_privileges(cursor, user, db):
    priv_map = {
        'C': 'CREATE',
        'T': 'TEMPORARY',
        'c': 'CONNECT',
    }
    query = 'SELECT datacl FROM pg_database WHERE datname = %s'
    cursor.execute(query, (db,))
    datacl = cursor.fetchone()[0]
    if datacl is None:
        return set()
    r = re.search(r'%s\\?"?=(C?T?c?)/[^,]+,?' % user, datacl)
    if r is None:
        return set()
    o = set()
    for v in r.group(1):
        o.add(priv_map[v])
    return normalize_privileges(o, 'database')


# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
def has_database_privileges(cursor, user, db, privs):
    """
    Return the difference between the privileges that a user already has and
    the privileges that they desire to have.

    :returns: tuple of:
        * privileges that they have and were requested
        * privileges they currently hold but were not requested
        * privileges requested that they do not hold
    """
    cur_privs = get_database_privileges(cursor, user, db)
    have_currently = cur_privs.intersection(privs)
    other_current = cur_privs.difference(privs)
    desired = privs.difference(cur_privs)
    return (have_currently, other_current, desired)


# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
def grant_database_privileges(cursor, user, db, privs):
    # Note: priv escaped by parse_privs
    privs = ', '.join(privs)
    if user == "PUBLIC":
        query = 'GRANT %s ON DATABASE %s TO PUBLIC' % (
                privs, pg_quote_identifier(db, 'database'))
    else:
        query = 'GRANT %s ON DATABASE %s TO "%s"' % (
                privs, pg_quote_identifier(db, 'database'), user)

    executed_queries.append(query)
    cursor.execute(query)


# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
def revoke_database_privileges(cursor, user, db, privs):
    # Note: priv escaped by parse_privs
    privs = ', '.join(privs)
    if user == "PUBLIC":
        query = 'REVOKE %s ON DATABASE %s FROM PUBLIC' % (
                privs, pg_quote_identifier(db, 'database'))
    else:
        query = 'REVOKE %s ON DATABASE %s FROM "%s"' % (
                privs, pg_quote_identifier(db, 'database'), user)

    executed_queries.append(query)
    cursor.execute(query)



def parse_role_attrs(role_attr_flags, srv_version):
    flags = frozenset(role.upper() for role in role_attr_flags.split(',') if role)

    valid_flags = frozenset(itertools.chain(FLAGS, get_valid_flags_by_version(srv_version)))
    valid_flags = frozenset(itertools.chain(valid_flags, ('NO%s' % flag for flag in valid_flags)))

    if not flags.issubset(valid_flags):
        raise InvalidFlagsError('Invalid role_attr_flags specified: %s' %
                                ' '.join(flags.difference(valid_flags)))

    return ' '.join(flags)


# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
def normalize_privileges(privs, type_):
    new_privs = set(privs)
    if 'ALL' in new_privs:
        new_privs.update(VALID_PRIVS[type_])
        new_privs.remove('ALL')
    if 'TEMP' in new_privs:
        new_privs.add('TEMPORARY')
        new_privs.remove('TEMP')

    return new_privs


# WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
def parse_privs(privs, db):
    """
    Parse privilege string to determine permissions for database db.
    Format:

        privileges[/privileges/...]

    Where:

        privileges := DATABASE_PRIVILEGES[,DATABASE_PRIVILEGES,...] |
            TABLE_NAME:TABLE_PRIVILEGES[,TABLE_PRIVILEGES,...]
    """
    if privs is None:
        return privs

    o_privs = {
        'database': {},
        'table': {}
    }
    for token in privs.split('/'):
        if ':' not in token:
            type_ = 'database'
            name = db
            priv_set = frozenset(x.strip().upper()
                                 for x in token.split(',') if x.strip())
        else:
            type_ = 'table'
            name, privileges = token.split(':', 1)
            priv_set = frozenset(x.strip().upper()
                                 for x in privileges.split(',') if x.strip())

        if not priv_set.issubset(VALID_PRIVS[type_]):
            raise InvalidPrivsError('Invalid privs specified for %s: %s' %
                                    (type_, ' '.join(priv_set.difference(VALID_PRIVS[type_]))))

        priv_set = normalize_privileges(priv_set, type_)
        o_privs[type_][name] = priv_set

    return o_privs


def get_valid_flags_by_version(srv_version):
    """
    Some role attributes were introduced after certain versions. We want to
    compile a list of valid flags against the current Postgres version.
    """
    return [
        flag
        for flag, version_introduced in FLAGS_BY_VERSION.items()
        if srv_version >= version_introduced
    ]


def get_comment(cursor, user):
    """Get user's comment."""
    query = ("SELECT pg_catalog.shobj_description(r.oid, 'pg_authid') "
             "FROM pg_catalog.pg_roles r "
             "WHERE r.rolname = %(user)s")
    cursor.execute(query, {'user': user})
    return cursor.fetchone()[0]


def add_comment(cursor, user, comment):
    """Add comment on user."""
    if comment != get_comment(cursor, user):
        query = 'COMMENT ON ROLE "%s" IS ' % user
        cursor.execute(query + '%(comment)s', {'comment': comment})
        executed_queries.append(cursor.mogrify(query + '%(comment)s', {'comment': comment}))
        return True
    else:
        return False


# ===========================================
# Module execution.
#

def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        user=dict(type='str', required=True, aliases=['name']),
        password=dict(type='str', default=None, no_log=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        priv=dict(type='str', default=None, removed_in_version='3.0.0', removed_from_collection='community.postgreql'),
        db=dict(type='str', default='', aliases=['login_db']),
        fail_on_user=dict(type='bool', default=True, aliases=['fail_on_role']),
        role_attr_flags=dict(type='str', default=''),
        encrypted=dict(type='bool', default=True),
        no_password_changes=dict(type='bool', default=False, no_log=False),
        expires=dict(type='str', default=None),
        conn_limit=dict(type='int', default=None),
        session_role=dict(type='str'),
        # WARNING: groups are deprecated and will  be removed in community.postgresql 3.0.0
        groups=dict(type='list', elements='str', removed_in_version='3.0.0', removed_from_collection='community.postgreql'),
        comment=dict(type='str', default=None),
        trust_input=dict(type='bool', default=True),
    )

    user = module.params["user"]
    password = module.params["password"]
    state = module.params["state"]
    fail_on_user = module.params["fail_on_user"]
    # WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
    if module.params['db'] == '' and module.params["priv"] is not None:
        module.fail_json(msg="privileges require a database to be specified")
    # WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
    privs = parse_privs(module.params["priv"], module.params["db"])
    no_password_changes = module.params["no_password_changes"]
    if module.params["encrypted"]:
        encrypted = "ENCRYPTED"
    else:
        encrypted = "UNENCRYPTED"
    expires = module.params["expires"]
    conn_limit = module.params["conn_limit"]
    role_attr_flags = module.params["role_attr_flags"]
    # WARNING: groups are deprecated and will  be removed in community.postgresql 3.0.0
    groups = module.params["groups"]
    if groups:
        groups = [e.strip() for e in groups]
    comment = module.params["comment"]
    session_role = module.params['session_role']

    trust_input = module.params['trust_input']
    if not trust_input:
        # Check input for potentially dangerous elements:
        # WARNING: groups are deprecated and will  be removed in community.postgresql 3.0.0
        check_input(module, user, password, privs, expires,
                    role_attr_flags, groups, comment, session_role)

    # Ensure psycopg2 libraries are available before connecting to DB:
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params)
    cursor = db_connection.cursor(cursor_factory=DictCursor)

    srv_version = get_server_version(db_connection)

    try:
        role_attr_flags = parse_role_attrs(role_attr_flags, srv_version)
    except InvalidFlagsError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    kw = dict(user=user)
    changed = False
    user_removed = False

    if state == "present":
        if user_exists(cursor, user):
            try:
                changed = user_alter(db_connection, module, user, password,
                                     role_attr_flags, encrypted, expires, no_password_changes, conn_limit)
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        else:
            try:
                changed = user_add(cursor, user, password,
                                   role_attr_flags, encrypted, expires, conn_limit)
            except psycopg2.ProgrammingError as e:
                module.fail_json(msg="Unable to add user with given requirement "
                                     "due to : %s" % to_native(e),
                                 exception=traceback.format_exc())
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        # WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
        try:
            changed = grant_privileges(cursor, user, privs) or changed
        except SQLParseError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

        # WARNING: groups are deprecated and will  be removed in community.postgresql 3.0.0
        if groups:
            target_roles = []
            target_roles.append(user)
            pg_membership = PgMembership(module, cursor, groups, target_roles)
            changed = pg_membership.grant() or changed
            executed_queries.extend(pg_membership.executed_queries)

        if comment is not None:
            try:
                changed = add_comment(cursor, user, comment) or changed
            except Exception as e:
                module.fail_json(msg='Unable to add comment on role: %s' % to_native(e),
                                 exception=traceback.format_exc())

    else:
        if user_exists(cursor, user):
            if module.check_mode:
                changed = True
                kw['user_removed'] = True
            else:
                # WARNING: privs are deprecated and will  be removed in community.postgresql 3.0.0
                try:
                    changed = revoke_privileges(cursor, user, privs)
                    user_removed = user_delete(cursor, user)
                except SQLParseError as e:
                    module.fail_json(msg=to_native(e), exception=traceback.format_exc())
                changed = changed or user_removed
                if fail_on_user and not user_removed:
                    msg = "Unable to remove user"
                    module.fail_json(msg=msg)
                kw['user_removed'] = user_removed

    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    kw['changed'] = changed
    kw['queries'] = executed_queries
    if debug_info:
        kw['debug_info'] = debug_info
    module.exit_json(**kw)


if __name__ == '__main__':
    main()