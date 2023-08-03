import argparse
from google.cloud import storage
from rich.console import Console
from internals import system
import os
import re
import time
import yaml

def should_exclude_file(file_name, exclude_patterns, exclude_names):
    _, extension = os.path.splitext(file_name)
    if extension in exclude_patterns:
        return True
    for name in exclude_names:
        if name in file_name:
            return True
    return False

def execute(args):
    results = []
    shouldDownload = True
    with open('connection.yml', 'r') as file:
        connections = yaml.safe_load(file)

    if 'sources' in connections:
        sources_config = connections['sources']
        fs_config = sources_config.get('fs')
        if fs_config:
            for key, config in fs_config.items():
                path = config.get('path') or os.getcwd()
                if not os.path.exists(path):
                    path = os.getcwd()
                exclude_patterns = fs_config.get('exclude_patterns') or []
                exclude_names = fs_config.get('exclude_names') or []
                files = system.list_all_files_iteratively(path, exclude_patterns, exclude_names)
                for file_path in files:
                    matches = system.read_match_strings(file_path, 'google_cloud_storage')
                    if matches:
                        for match in matches:
                            results.append({
                                'host': 'This PC',
                                'file_path': file_path,
                                'pattern_name': match['pattern_name'],
                                'matches': match['matches'],
                                'sample_text': match['sample_text'],
                                'profile': key,
                                'data_source': 'fs'
                            })
        else:
            system.print_error("No filesystem 'fs' connection details found in connection.yml")
    else:
        system.print_error("No 'sources' section found in connection.yml")
    return results
