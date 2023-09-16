import psycopg2
from hawk_scanner.internals import system
from rich.console import Console
from rich.table import Table

console = Console()

def connect_postgresql(host, port, user, password, database):
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        if conn:
            system.print_info(f"Connected to PostgreSQL database at {host}")
            return conn
    except Exception as e:
        system.print_error(f"Failed to connect to PostgreSQL database at {host} with error: {e}")

def check_data_patterns(conn, patterns, profile_name, database_name):
    cursor = conn.cursor()
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    tables = [table[0] for table in cursor.fetchall()]
    table_count = 1
    results = []
    for table in tables:
        cursor.execute(f"SELECT * FROM {table}")
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
                                'host': conn.dsn,
                                'database': database_name,
                                'table': table,
                                'column': column,
                                'pattern_name': match['pattern_name'],
                                'matches': match['matches'],
                                'sample_text': match['sample_text'],
                                'profile': profile_name,
                                'data_source': 'postgresql'
                            })

            data_count += 1

        table_count += 1

    cursor.close()
    return results

def execute(args):
    results = []
    system.print_info(f"Running Checks for PostgreSQL Sources")
    connections = system.get_connection()

    if 'sources' in connections:
        sources_config = connections['sources']
        postgresql_config = sources_config.get('postgresql')

        if postgresql_config:
            patterns = system.get_fingerprint_file()

            for key, config in postgresql_config.items():
                host = config.get('host')
                user = config.get('user')
                port = config.get('port', 5432)  # default port for PostgreSQL
                password = config.get('password')
                database = config.get('database')

                if host and user and password and database:
                    system.print_info(f"Checking PostgreSQL Profile {key} and database {database}")
                    conn = connect_postgresql(host, port, user, password, database)
                    if conn:
                        results += check_data_patterns(conn, patterns, key, database)
                        conn.close()
                else:
                    system.print_error(f"Incomplete PostgreSQL configuration for key: {key}")
        else:
            system.print_error("No PostgreSQL connection details found in connection.yml")
    else:
        system.print_error("No 'sources' section found in connection.yml")
    return results
