import pymysql
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def connect_mysql(args, host, port, user, password, database):
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        if conn:
            system.print_info(args, f"Connected to MySQL database at {host}")
            return conn
    except Exception as e:
        system.print_error(args, f"Failed to connect to MySQL database at {host} with error: {e}")

def check_data_patterns(args, conn, patterns, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_tables=None, exclude_columns=None):
    cursor = conn.cursor()
    
    # Get the list of tables to scan
    cursor.execute("SHOW TABLES")
    tables = [table[0] for table in cursor.fetchall()]
    if whitelisted_tables:
        tables_to_scan = [table for table in tables if table in whitelisted_tables]
    else:
        tables_to_scan = tables or []

    table_count = 1

    results = []
    for table in tables_to_scan:
        cursor.execute(f"SELECT * FROM {table} LIMIT {limit_end} OFFSET {limit_start}")
        columns = [column[0] for column in cursor.description]

        data_count = 1
        for row in cursor.fetchall():
            for column, value in zip(columns, row):
                if exclude_columns and column in exclude_columns:
                    continue
                if value:
                    value_str = str(value)
                    matches = system.match_strings(args, value_str)
                    if matches:
                        for match in matches:
                            results.append({
                                'host': conn.get_host_info(),
                                'database': database_name,
                                'table': table,
                                'column': column,
                                'pattern_name': match['pattern_name'],
                                'matches': match['matches'],
                                'sample_text': match['sample_text'],
                                'profile': profile_name,
                                'data_source': 'mysql'
                            })

            data_count += 1

        table_count += 1

    cursor.close()
    return results

def execute(args):
    results = []
    system.print_info(args, f"Running Checks for MySQL Sources")
    connections = system.get_connection(args)
    if 'sources' in connections:
        sources_config = connections['sources']
        mysql_config = sources_config.get('mysql')

        if mysql_config:
            patterns = system.get_fingerprint_file(args)

            for key, config in mysql_config.items():
                host = config.get('host')
                user = config.get('user')
                port = config.get('port', 3306)  # default port for MySQL
                password = config.get('password')
                database = config.get('database')
                limit_start = config.get('limit_start', 0)
                limit_end = config.get('limit_end', 500)
                tables = config.get('tables', [])
                exclude_columns = config.get('exclude_columns', [])

                if host and user and database:
                    system.print_info(args, f"Checking MySQL Profile {key} and database {database}")
                    conn = connect_mysql(args, host, port, user, password, database)
                    if conn:
                        results += check_data_patterns(args, conn, patterns, key, database, limit_start=limit_start, limit_end=limit_end, whitelisted_tables=tables, exclude_columns=exclude_columns)
                        conn.close()
                else:
                    system.print_error(args, f"Incomplete MySQL configuration for key: {key}")
        else:
            system.print_error(args, "No MySQL connection details found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")
    return results

# Example usage
if __name__ == "__main__":
    execute(None)
