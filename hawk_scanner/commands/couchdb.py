import couchdb
from hawk_scanner.internals import system
from rich.console import Console
from rich.table import Table

console = Console()

def connect_couchdb(host, port, username, password, database):
    try:
        server = couchdb.Server(f"http://{username}:{password}@{host}:{port}/")
        if database not in server:
            system.print_error(f"Database {database} not found on CouchDB server.")
            return None
        db = server[database]
        system.print_info(f"Connected to CouchDB database")
        return db
    except Exception as e:
        system.print_error(f"Failed to connect to CouchDB database with error: {e}")
        return None

def check_data_patterns(db, patterns, profile_name, database_name):
    results = []
    for doc_id in db:
        document = db[doc_id]
        for field_name, field_value in document.items():
            if field_value:
                value_str = str(field_value)
                matches = system.analyze_strings(value_str, 'couchdb')
                if matches:
                    for match in matches:
                        results.append({
                            'host': f"{db.resource.credentials[1]}:{db.resource.credentials[2]}",
                            'database': database_name,
                            'document_id': doc_id,
                            'field': field_name,
                            'pattern_name': match['pattern_name'],
                            'matches': match['matches'],
                            'sample_text': match['sample_text'],
                            'profile': profile_name,
                            'data_source': 'couchdb'
                        })

    return results

def execute(args, programmatic=False):
    try:
        results = []
        system.print_info(f"Running Checks for CouchDB Sources")
        connections = system.get_connection(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            couchdb_config = sources_config.get('couchdb')

            if couchdb_config:
                patterns = system.get_fingerprint_file(args, programmatic)

                for key, config in couchdb_config.items():
                    host = config.get('host')
                    port = config.get('port', 5984)  # default CouchDB port
                    username = config.get('username')
                    password = config.get('password')
                    database = config.get('database')

                    if host and username and password and database:
                        system.print_info(f"Checking CouchDB Profile {key} with host and authentication")
                    else:
                        system.print_error(f"Incomplete CouchDB configuration for key: {key}")
                        continue

                    db = connect_couchdb(host, port, username, password, database)
                    if db:
                        results += check_data_patterns(db, patterns, key, database)
            else:
                system.print_error("No CouchDB connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Failed to execute CouchDB checks with error: {e}")
    return results
