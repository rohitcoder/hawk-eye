import psycopg2
from psycopg2 import sql
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

# Schemas owned by PostgreSQL itself, never user data.
SYSTEM_SCHEMAS = ('pg_catalog', 'information_schema')


def connect_postgresql(args, host, port, user, password, database):
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        if conn:
            system.print_info(args, f"Connected to PostgreSQL database at {host}")
            return conn
    except Exception as e:
        system.print_error(args, f"Failed to connect to PostgreSQL database at {host} with error: {e}")


def get_tables_to_scan(cursor, whitelisted_tables=None):
    """Return the (schema, table) pairs to scan.

    Covers every non-system schema, not just 'public', and includes views.
    A whitelist entry may be given as 'table' (matched in any schema) or as
    a qualified 'schema.table'.
    """
    cursor.execute(
        """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_schema NOT IN %s
        ORDER BY table_schema, table_name
        """,
        (SYSTEM_SCHEMAS,)
    )
    all_tables = cursor.fetchall()

    if not whitelisted_tables:
        return all_tables

    wanted = set(whitelisted_tables)
    return [
        (schema, table) for schema, table in all_tables
        if table in wanted or f"{schema}.{table}" in wanted
    ]


def check_data_patterns(args, conn, patterns, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_tables=None, exclude_columns=None):
    cursor = conn.cursor()
    results = []

    try:
        tables_to_scan = get_tables_to_scan(cursor, whitelisted_tables)

        if whitelisted_tables:
            found = {t for _, t in tables_to_scan} | {f"{s}.{t}" for s, t in tables_to_scan}
            for missing in sorted(set(whitelisted_tables) - found):
                system.print_error(args, f"Table {missing} not found in database {database_name}. Skipping.")

        if not tables_to_scan:
            if whitelisted_tables:
                system.print_info(args, f"No matching tables to scan in database {database_name}. Check the 'tables' list in your connection.yml, or remove it to scan every table.")
            else:
                system.print_info(args, f"No tables found in database {database_name}. The database is empty, or this user cannot see any tables (needs USAGE on the schema and SELECT on its tables).")
            return results

        schemas = sorted({schema for schema, _ in tables_to_scan})
        system.print_info(args, f"Scanning {len(tables_to_scan)} table(s) across {len(schemas)} schema(s) in {database_name}: {', '.join(schemas)}")

        host_info = get_host_info(conn)
        unreadable = 0

        for schema, table in tables_to_scan:
            qualified_name = f"{schema}.{table}"
            try:
                # Identifiers are quoted so that mixed-case names, names with
                # spaces and reserved words resolve to the intended table.
                cursor.execute(
                    sql.SQL("SELECT * FROM {} LIMIT %s OFFSET %s").format(
                        sql.Identifier(schema, table)
                    ),
                    (limit_end, limit_start)
                )
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
            except Exception as e:
                # One unreadable table must not discard the whole scan.
                unreadable += 1
                system.print_error(args, f"Skipping table {qualified_name}, could not read it: {e}")
                conn.rollback()
                continue

            for row in rows:
                for column, value in zip(columns, row):
                    if exclude_columns and (column in exclude_columns or f"{qualified_name}.{column}" in exclude_columns):
                        continue
                    if value:
                        value_str = str(value)
                        matches = system.match_strings(args, value_str)
                        if matches:
                            for match in matches:
                                results.append({
                                    'host': host_info,
                                    'database': database_name,
                                    'table': qualified_name,
                                    'column': column,
                                    'pattern_name': match['pattern_name'],
                                    'matches': match['matches'],
                                    'sample_text': match['sample_text'],
                                    'profile': profile_name,
                                    'data_source': 'postgresql'
                                })
        if unreadable:
            system.print_info(args, f"Skipped {unreadable} unreadable table(s) in {database_name}. Grant SELECT on them to include them in the scan.")
    finally:
        cursor.close()

    return results


def get_host_info(conn):
    """host:port for the connection, matching what the other sources report."""
    params = conn.get_dsn_parameters()
    return f"{params.get('host', '')}:{params.get('port', '')}"


def execute(args):
    results = []
    system.print_info(args, f"Running Checks for PostgreSQL Sources")
    connections = system.get_connection(args)

    if 'sources' in connections:
        sources_config = connections['sources']
        postgresql_config = sources_config.get('postgresql')

        if postgresql_config:
            patterns = system.get_fingerprint_file(args)

            for key, config in postgresql_config.items():
                host = config.get('host')
                user = config.get('user')
                port = config.get('port', 5432)  # default port for PostgreSQL
                password = config.get('password')
                database = config.get('database')
                limit_start = config.get('limit_start', 0)
                limit_end = config.get('limit_end', 500)
                tables = config.get('tables', [])
                exclude_columns = config.get('exclude_columns', [])

                if host and user and password and database:
                    system.print_info(args, f"Checking PostgreSQL Profile {key}, database {database}")
                    conn = connect_postgresql(args, host, port, user, password, database)
                    if conn:
                        profile_results = check_data_patterns(args, conn, patterns, key, database, limit_start=limit_start, limit_end=limit_end, whitelisted_tables=tables, exclude_columns=exclude_columns)
                        if not profile_results:
                            system.print_info(args, f"No matches found in database {database} for profile {key}. If you expected results, check limit_start/limit_end and that this user can read the tables holding the data.")
                        results += profile_results
                        conn.close()
                else:
                    system.print_error(args, f"Incomplete PostgreSQL configuration for key: {key}")
        else:
            system.print_error(args, "No PostgreSQL connection details found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")
    return results

# Example usage
if __name__ == "__main__":
    execute(None)
