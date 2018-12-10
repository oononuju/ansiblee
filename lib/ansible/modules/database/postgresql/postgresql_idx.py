#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Andrey Klychkov (@Andersson007) <aaklychkov@mail.ru>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: postgresql_idx
short_description: Creates or drops indexes from a PostgreSQL database.
description:
   - Create or drop indexes from a remote PostgreSQL database.
version_added: "2.8"
options:
  idxname:
    description:
      - Name of the index to add or remove.
    required: true
  db:
    description:
      - Name of database where the index will be created/removed.
  port:
    description:
      - Database port to connect.
    default: 5432
  login_user:
    description:
      - User (role) used to authenticate with PostgreSQL.
    default: postgres
  login_password:
    description:
      - Password used to authenticate with PostgreSQL.
  login_host:
    description:
      - Host running PostgreSQL.
  login_unix_socket:
    description:
      - Path to a Unix domain socket for local connections.
  ssl_mode:
    description:
      - Determines whether or with what priority a secure SSL TCP/IP connection
        will be negotiated with the server.
      - See U(https://www.postgresql.org/docs/current/static/libpq-ssl.html) for
        more information on the modes.
      - Default of C(prefer) matches libpq default.
    default: prefer
    choices: ["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]
  ssl_rootcert:
    description:
      - Specifies the name of a file containing SSL certificate authority (CA)
        certificate(s). If the file exists, the server's certificate will be
        verified to be signed by one of these authorities.
  state:
    description:
      - Index state.
    default: present
    choices: ["present", "absent"]
  table:
    description:
      - Table of the index.
    required: true
  columns:
    description:
      - List of index columns.
  cond:
    description:
      - Index conditions.
  idxtype:
    description:
      - Index type (like btree, gist, gin, etc.).
  concurrent:
    description:
      - Enable or disable concurrent mode (CREATE / DROP INDEX CONCURRENTLY).
    default: yes
    type: bool
notes:
   - The default authentication assumes that you are either logging in as or
     sudo'ing to the postgres account on the host.
   - This module uses psycopg2, a Python PostgreSQL database adapter. You must
     ensure that psycopg2 is installed on the host before using this module. If
     the remote host is the PostgreSQL server (which is the default case), then
     PostgreSQL must also be installed on the remote host. For Ubuntu-based
     systems, install the postgresql, libpq-dev, and python-psycopg2 packages
     on the remote host before using this module.
requirements: [ psycopg2 ]
author: "Andrew Klychkov (@Andersson007)"
'''

EXAMPLES = '''
# Create btree index test_idx concurrently covering columns id and name of table products
- postgresql_idx:
    db: acme
    table: products
    columns: id,name
    idxname: test_idx

# Create gist index test_gist_idx concurrently on column geo_data of table map
- postgresql_idx:
    db: somedb
    table: map
    idxtype: gist
    columns: geo_data
    idxname: test_gist_idx

# Create gin index gin0_idx not concurrently on column comment of table test
# (Note: pg_trgm extention must be installed for gin_trgm_ops)
- postgresql_idx:
    idxname: gin0_idx
    table: test
    columns: comment gin_trgm_ops
    concurrent: no
    idxtype: gin

# Drop btree test_idx concurrently
- postgresql_idx:
    db: mydb
    idxname: test__idx
    state: absent

# Create btree index test_idx concurrently on columns id,comment where column id > 1
- postgresql_idx:
    db: mydb
    table: test
    columns: id,comment
    idxname: test_idx
    cond: id > 1
'''

RETURN = ''' # '''


import traceback
from hashlib import md5

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    postgresqldb_found = False
else:
    postgresqldb_found = True

import ansible.module_utils.postgres as pgutils
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.database import SQLParseError
from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems


VALID_IDX_TYPES = ('BTREE', 'HASH', 'GIST', 'SPGIST', 'GIN', 'BRIN')


# ===========================================
# PostgreSQL module specific support methods.
#


def index_exists(cursor, idxname):
    query = "SELECT indexname FROM pg_indexes "\
            "WHERE indexname = '%s'" % idxname
    cursor.execute(query)
    exists = cursor.fetchone()
    if exists is not None:
        return True
    return False


def index_valid(cursor, idxname, module):
    query = "SELECT i.indisvalid FROM pg_catalog.pg_index AS i "\
            "WHERE i.indexrelid = (SELECT oid "\
            "FROM pg_class WHERE relname = '%s')" % idxname
    cursor.execute(query)
    valid = cursor.fetchone()
    if valid is None:
        module.fail_json(msg="Validity check: returns "
                             "no information about %s" % idxname)
    return valid


def index_create(cursor, module, idxname, tblname, idxtype,
                 columns, cond, concurrent=True):
    """Create new index"""
    changed = False
    if idxtype is None:
        idxtype = "BTREE"

    mode = 'CONCURRENTLY'
    if not concurrent:
        mode = ''

    if cond is None:
        condition = ''
    else:
        condition = 'WHERE %s' % cond

    if cond is not None:
        cond = " WHERE %s" % cond

    for column in columns.split(','):
        column.strip()

    query = "CREATE INDEX %s %s ON %s USING %s (%s)%s" % (
        mode, idxname, tblname, idxtype, columns, condition)

    try:
        if index_exists(cursor, idxname):
            return False

        cursor.execute(query)
        # In any case, even the created index is not valid,
        # the database schema has been changed:
        changed = True
    except psycopg2.InternalError as e:
        if e.pgcode == '25006':
            # Handle errors due to read-only transactions indicated by pgcode 25006
            # ERROR:  cannot execute ALTER ROLE in a read-only transaction
            changed = False
            module.fail_json(msg=e.pgerror, exception=traceback.format_exc())
            return changed
        else:
            raise psycopg2.InternalError(e)
    return changed


def index_drop(cursor, module, idxname, concurrent=True):
    """Drop index"""
    changed = False
    if not index_exists(cursor, idxname):
        return changed

    mode = 'CONCURRENTLY'
    if not concurrent:
        mode = ''

    query = 'DROP INDEX %s %s' % (mode, idxname)
    try:
        cursor.execute(query)
        changed = True
    except psycopg2.InternalError as e:
        if e.pgcode == '25006':
            # Handle errors due to read-only transactions indicated by pgcode 25006
            # ERROR:  cannot execute ALTER ROLE in a read-only transaction
            changed = False
            module.fail_json(msg=e.pgerror, exception=traceback.format_exc())
            return changed
        else:
            raise psycopg2.InternalError(e)
    return changed


# ===========================================
# Module execution.
#


def main():
    argument_spec = pgutils.postgres_common_argument_spec()
    argument_spec.update(dict(
        idxname=dict(required=True, aliases=['idxname']),
        db=dict(default=''),
        ssl_mode=dict(default='prefer', choices=[
            'disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']),
        ssl_rootcert=dict(default=None),
        state=dict(default="present", choices=["absent", "present"]),
        concurrent=dict(type=bool, default="yes"),
        table=dict(default=None),
        idxtype=dict(default=None),
        columns=dict(default=None),
        cond=dict(default=None)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    idxname = module.params["idxname"]
    db = module.params["db"]
    state = module.params["state"]
    concurrent = module.params["concurrent"]
    table = module.params["table"]
    idxtype = module.params["idxtype"]
    columns = module.params["columns"]
    cond = module.params["cond"]
    sslrootcert = module.params["ssl_rootcert"]

    if state == 'present':
        if table is None:
            module.fail_json(msg="Table must be specified")
        if columns is None:
            module.fail_json(msg="At least one column must be specified")
    else:
        if table is not None:
            module.fail_json(msg="Index is going to be removed, so "
                                 "it does not make sence to pass a table name")
        if columns is not None:
            module.fail_json(msg="Index is going to be removed, so "
                                 "it does not make sence to pass column names")
        if cond is not None:
            module.fail_json(msg="Index is going to be removed, so "
                                 "it does not make sence to pass any conditions")
        if idxtype is not None:
            module.fail_json(msg="Index is going to be removed, so "
                                 "it does not make sence to pass an index type")

    if not postgresqldb_found:
        module.fail_json(msg="the python psycopg2 module is required")

    # To use defaults values, keyword arguments must be absent, so
    # check which values are empty and don't include in the **kw
    # dictionary
    params_map = {
        "login_host": "host",
        "login_user": "user",
        "login_password": "password",
        "port": "port",
        "db": "database",
        "ssl_mode": "sslmode",
        "ssl_rootcert": "sslrootcert"
    }
    kw = dict((params_map[k], v) for (k, v) in iteritems(module.params)
              if k in params_map and v != "" and v is not None)

    # If a login_unix_socket is specified, incorporate it here.
    is_localhost = "host" not in kw or kw["host"] == "" or kw["host"] == "localhost"
    if is_localhost and module.params["login_unix_socket"] != "":
        kw["host"] = module.params["login_unix_socket"]

    if psycopg2.__version__ < '2.4.3' and sslrootcert is not None:
        module.fail_json(
            msg='psycopg2 must be at least 2.4.3 in order to user the ssl_rootcert parameter')

    if module.check_mode and concurrent:
            module.fail_json(msg="Cannot concurrently create or drop index "
                                 "inside the transaction block. "
                                 "The check is possible in not concurrent mode only")

    try:
        db_connection = psycopg2.connect(**kw)
        if concurrent:
            db_connection.set_session(autocommit=True)

        cursor = db_connection.cursor(
            cursor_factory=psycopg2.extras.DictCursor)
    except TypeError as e:
        if 'sslrootcert' in e.args[0]:
            module.fail_json(
                msg='Postgresql server must be at least version 8.4 to support sslrootcert')
        module.fail_json(msg="unable to connect to database: %s" % to_native(e),
                         exception=traceback.format_exc())
    except Exception as e:
        module.fail_json(msg="unable to connect to database: %s" % to_native(e),
                         exception=traceback.format_exc())

    if state == 'present' and index_exists(cursor, idxname):
        kw['changed'] = False
        module.exit_json(**kw)

    changed = False

    if state == "present":
        if idxtype is not None and idxtype.upper() not in VALID_IDX_TYPES:
            module.fail_json(msg="Index type is not in valid types" % idxname)

        try:
            changed = index_create(cursor, module, idxname, table,
                                   idxtype, columns, cond, concurrent)
            kw['index_created'] = True
        except SQLParseError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        except psycopg2.ProgrammingError as e:
            module.fail_json(msg="Unable to create index with given "
                                 "requirement due to : %s" % to_native(e),
                             exception=traceback.format_exc())
    else:
        try:
            changed = index_drop(cursor, module, idxname, concurrent)
            kw['index_dropped'] = True
        except SQLParseError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        except psycopg2.ProgrammingError as e:
            module.fail_json(msg="Unable to drop index due to : %s" % to_native(e),
                             exception=traceback.format_exc())

    if not concurrent:
        if changed:
            if module.check_mode:
                db_connection.rollback()
            else:
                db_connection.commit()

    if not module.check_mode and state != 'absent':
        if not index_valid(cursor, idxname, module):
            kw['changed'] = changed
            module.fail_json(msg="Index %s is invalid!" % idxname)

    kw['changed'] = changed
    module.exit_json(**kw)


if __name__ == '__main__':
    main()
