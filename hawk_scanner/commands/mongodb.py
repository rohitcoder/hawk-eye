import pymongo
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def connect_mongodb(host, port, username, password, database, uri=None):
    try:
        if uri:
            client = pymongo.MongoClient(uri)
        else:
            client = pymongo.MongoClient(host=host, port=port, username=username, password=password)

        if database not in client.list_database_names():
            system.print_error(f"Database {database} not found on MongoDB server.")
            return None

        db = client[database]
        system.print_info(f"Connected to MongoDB database")
        return db
    except Exception as e:
        system.print_error(f"Failed to connect to MongoDB database with error: {e}")
        return None


def check_data_patterns(db, patterns, profile_name, database_name, limit_start=0, limit_end=500, whitelisted_collections=None):
    results = []
    all_collections = db.list_collection_names()

    if whitelisted_collections:
        collections_to_scan = [collection for collection in all_collections if collection in whitelisted_collections]
    else:
        collections_to_scan = all_collections or []

    for collection_name in collections_to_scan:
        if collection_name not in all_collections:
            system.print_warning(f"Collection {collection_name} not found in the database. Skipping.")
            continue

        collection = db[collection_name]
        for document in collection.find().limit(limit_end).skip(limit_start):
            for field_name, field_value in document.items():
                if field_value:
                    value_str = str(field_value)
                    matches = system.analyze_strings(value_str)
                    if matches:
                        for match in matches:
                            results.append({
                                'host': db.client.address[0],
                                'database': database_name,
                                'collection': collection_name,
                                'field': field_name,
                                'pattern_name': match['pattern_name'],
                                'matches': match['matches'],
                                'sample_text': match['sample_text'],
                                'profile': profile_name,
                                'data_source': 'mongodb'
                            })

    return results

def execute(args, programmatic=False):
    try:
        results = []
        system.print_info(f"Running Checks for MongoDB Sources")
        connections = system.get_connection(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            mongodb_config = sources_config.get('mongodb')

            if mongodb_config:
                patterns = system.get_fingerprint_file(args, programmatic)

                for key, config in mongodb_config.items():
                    host = config.get('host')
                    port = config.get('port', 27017)  # default MongoDB port
                    username = config.get('username')
                    password = config.get('password')
                    database = config.get('database')
                    uri = config.get('uri')  # Added support for URI
                    limit_start = config.get('limit_start', 0)
                    limit_end = config.get('limit_end', 500)
                    collections = config.get('collections', [])

                    if uri:
                        system.print_info(f"Checking MongoDB Profile {key} using URI")
                    elif host and username and password and database:
                        system.print_info(f"Checking MongoDB Profile {key} with host and authentication")
                    else:
                        system.print_error(f"Incomplete MongoDB configuration for key: {key}")
                        continue

                    db = connect_mongodb(host, port, username, password, database, uri)
                    if db:
                        results += check_data_patterns(db, patterns, key, database, limit_start=limit_start, limit_end=limit_end, whitelisted_collections=collections)
            else:
                system.print_error("No MongoDB connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Failed to run MongoDB checks with error: {e}")
    return results

# Example usage
if __name__ == "__main__":
    execute(None)
