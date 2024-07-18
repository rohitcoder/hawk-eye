from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def check_data_patterns(args, value, patterns, profile_name):
    value_str = str(value)
    matches = system.match_strings(args, value_str)
    results = []
    if matches:
        for match in matches:
            results.append({
                'pattern_name': match['pattern_name'],
                'matches': match['matches'],
                'sample_text': match['sample_text'],
                'profile': profile_name,
                'data_source': 'text'
            })
    return results

def execute(args):
    results = []
    system.print_info(args, f"Running Checks for Simple text")
    connections = system.get_connection(args)
    patterns = system.get_fingerprint_file(args)
    if 'sources' in connections:
        sources_config = connections['sources']
        text_config = sources_config.get('text')

        if text_config:
            for key, config in text_config.items():
                text = config.get('text', None)
                results += check_data_patterns(args, text, patterns, key)
        else:
            system.print_error(args, "No text connection details found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")
    return results

# Example usage
if __name__ == "__main__":
    execute(None)
