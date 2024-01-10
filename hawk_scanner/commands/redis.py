import redis
import yaml
from hawk_scanner.internals import system
from rich.console import Console


console = Console()

def connect_redis(host, port):
    try:
        r = redis.Redis(host=host, port=port)
        if r.ping():
            system.print_info(f"Redis instance at {host}:{port} is accessible")
            return r
        else:
            system.print_error(f"Redis instance at {host}:{port} is not accessible")
    except Exception as e:
        system.print_error(f"Redis instance at {host}:{port} is not accessible with error: {e}")

def get_patterns_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        patterns = yaml.safe_load(file)
        return patterns

def check_data_patterns(redis_instance, patterns, profile_name, host):

    results = []
    keys = redis_instance.keys('*')
    for key in keys:
        data = redis_instance.get(key)
        if data:
            data_str = data.decode('utf-8')
            matches = system.match_strings(data_str)
            if matches:
                for match in matches:
                    results.append({
                        'host': host,
                        'key': key.decode('utf-8'),
                        'pattern_name': match['pattern_name'],
                        'matches': match['matches'],
                        'sample_text': match['sample_text'],
                        'profile': profile_name,
                        'data_source': 'redis'
                    })
    return results

def execute(args, programmatic=False):
    try:
        results = []
        connections = system.get_connection(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            redis_config = sources_config.get('redis')

            if redis_config:
                patterns = system.get_fingerprint_file(args, programmatic)

                for profile_name, config in redis_config.items():
                    host = config.get('host')
                    port = config.get('port', 6379)

                    if host:
                        redis_instance = connect_redis(host, port)
                        if redis_instance:
                            results = check_data_patterns(redis_instance, patterns, profile_name, host)
                            redis_instance.close()
                    else:
                        system.print_error(f"Incomplete Redis configuration for key: {profile_name}")
            else:
                system.print_error("No Redis connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Error: {e}")
    return results
