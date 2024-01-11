import argparse, os, concurrent.futures, time
from google.cloud import storage
from rich.console import Console
from hawk_scanner.internals import system

def process_file(file_path, key, connections, fingerprints, programmatic=False):
    matches = system.analyze_file(file_path, 'fs', connections, fingerprints, programmatic=programmatic)
    file_data = system.getFileData(file_path)
    results = []
    if matches:
        for match in matches:
            results.append({
                'host': 'This PC',
                'file_path': file_path,
                'pattern_name': match['pattern_name'],
                'matches': match['matches'],
                'sample_text': match['sample_text'],
                'profile': key,
                'data_source': 'fs',
                'file_data': file_data
            })
    return results

def execute(args, programmatic=False):
    try:
        results = []
        connections = system.get_connection(args, programmatic)
        fingerprints = system.get_fingerprint_file(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            fs_config = sources_config.get('fs')
            if fs_config:
                for key, config in fs_config.items():
                    if 'path' not in config:
                        system.print_error(f"Path not found in fs profile '{key}'")
                        continue
                    path = config.get('path')
                    if not os.path.exists(path):
                        system.print_error(f"Path '{path}' does not exist")
                    
                    exclude_patterns = fs_config.get(key, {}).get('exclude_patterns', [])
                    start_time = time.time()
                    files = system.list_all_files_iteratively(path, exclude_patterns)
                    
                    # Use ThreadPoolExecutor for parallel processing
                    file_count = 0
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        futures = []
                        for file_path in files:
                            file_count += 1
                            results += process_file(file_path, key, connections, fingerprints, programmatic=programmatic)
                        
                        # Wait for all tasks to complete
                        concurrent.futures.wait(futures)
                    end_time = time.time()
                    elapsed_time = round(end_time - start_time, 2)
                    system.print_info(f"Time taken to analyze {file_count} files: {elapsed_time} seconds")
            else:
                system.print_error("No filesystem 'fs' connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Error in executing filesystem checks: {e}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Add your command-line arguments here if needed
    args = parser.parse_args()
    results = execute(args)
    # Handle results as needed
