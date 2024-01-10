from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def check_data_patterns(value, patterns, profile_name):
    value_str = str(value)
    matches = system.analyze_strings(value_str)
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

def execute(args, programmatic=False):
    try:
        results = []
        system.print_info(f"Running Checks for Simple text")
        connections = system.get_connection(args, programmatic)
        patterns = system.get_fingerprint_file(args, programmatic)
        if 'sources' in connections:
            sources_config = connections['sources']
            text_config = sources_config.get('text')
            if text_config:
                for key, config in text_config.items():
                    text = config.get('text', None)
                    results += check_data_patterns(text, patterns, key)
            else:
                system.print_error("No text connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Failed to connect to text with error: {e}")
    return results

# Example usage
if __name__ == "__main__":
    execute(None)
