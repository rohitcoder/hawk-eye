import pymysql
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def connect_mysql(host, port, user, password, database):
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        if conn:
            system.print_info(f"Connected to MySQL database at {host}")
            return conn
    except Exception as e:
        system.print_error(f"Failed to connect to MySQL database at {host} with error: {e}")

def check_data_patterns(conn, patterns, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_tables=None):
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
                if value:
                    value_str = str(value)
                    matches = system.match_strings(value_str)
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

def execute(args, programmatic=False):
    try:
        results = []
        system.print_info(f"Running Checks for MySQL Sources")
        connections = system.get_connection(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            mysql_config = sources_config.get('mysql')

            if mysql_config:
                patterns = system.get_fingerprint_file(args, programmatic)

                for key, config in mysql_config.items():
                    host = config.get('host')
                    user = config.get('user')
                    port = config.get('port', 3306)  # default port for MySQL
                    password = config.get('password')
                    database = config.get('database')
                    limit_start = config.get('limit_start', 0)
                    limit_end = config.get('limit_end', 500)
                    tables = config.get('tables', [])

                    if host and user and database:
                        system.print_info(f"Checking MySQL Profile {key} and database {database}")
                        conn = connect_mysql(host, port, user, password, database)
                        if conn:
                            results += check_data_patterns(conn, patterns, key, database, limit_start=limit_start, limit_end=limit_end, whitelisted_tables=tables)
                            conn.close()
                    else:
                        system.print_error(f"Incomplete MySQL configuration for key: {key}")
            else:
                system.print_error("No MySQL connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Failed to run MySQL checks with error: {e}")
    return results

# Example usage
if __name__ == "__main__":
    execute(None)
