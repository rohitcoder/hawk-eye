import argparse
import yaml
import mysql.connector
from internals import system
import re
from rich.console import Console
from rich.table import Table

console = Console()

def connect_mysql(host, port, user, password, database):
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        if conn.is_connected():
            console.print(f"[blue][DEBUG][/blue] Connected to MySQL database at [bold]{host}[/bold]")
            return conn
        else:
            console.print(f"[bold red]❌ Failed[/bold red] to connect to MySQL database at [bold]{host}[/bold]")
    except Exception as e:
        console.print(f"[bold red]❌ Failed[/bold red] to connect to MySQL database at [bold]{host}[/bold] with error: {e}")

def get_patterns_from_file(file_path):
    with open(file_path, 'r') as file:
        patterns = yaml.safe_load(file)
        return patterns

def check_data_patterns(conn, patterns, profile_name, database_name):
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
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
                                'host': conn._host,
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
    system.print_info(f"Running Checks for MySQL Sources")
    with open('connection.yml', 'r') as file:
        connections = yaml.safe_load(file)

    if 'sources' in connections:
        sources_config = connections['sources']
        mysql_config = sources_config.get('mysql')

        if mysql_config:
            fingerprint_file = 'fingerprint.yml'
            patterns = get_patterns_from_file(fingerprint_file)

            for key, config in mysql_config.items():
                host = config.get('host')
                user = config.get('user')
                port = config.get('port', 3306)  # default port
                password = config.get('password')
                database = config.get('database')

                if host and user and password and database:
                    console.print(f"[blue][DEBUG][/blue] Checking MySQL Profile [bold]'{key}'[/bold] and database [bold]'{database}'[/bold]")
                    conn = connect_mysql(host, port, user, password, database)
                    if conn:
                        results = check_data_patterns(conn, patterns, key, database)
                        conn.close()
                else:
                    console.print(f"Incomplete MySQL configuration for key: {key}")
        else:
            console.print("No MySQL connection details found in connection.yml")
    else:
        console.print("No 'sources' section found in connection.yml")
    return results
