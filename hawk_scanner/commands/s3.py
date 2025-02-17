import boto3
import os
import time
import yaml
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def connect_s3(args, access_key, secret_key, bucket_name):
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        s3 = session.resource('s3')
        bucket = s3.Bucket(bucket_name)
        system.print_info(args, f"Connected to S3 bucket: {bucket_name}")
        return bucket
    except Exception as e:
        system.print_error(args, f"[bold red]Failed[/bold red] to connect to S3 bucket: {e}")

def get_last_update_time(obj):
    last_modified = obj.last_modified
    if last_modified:
        return time.mktime(last_modified.timetuple())
    return None

def get_patterns_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        patterns = yaml.safe_load(file)
        return patterns

def execute(args):
    results = []
    shouldDownload = True
    system.print_info(args, f"Running Checks for S3 Sources")
    connections = system.get_connection(args)
    options = connections.get('options', {})
    quick_exit = options.get('quick_exit', False)
    max_matches = None
    if quick_exit:
        max_matches = options.get('max_matches', 1)
        system.print_info(args, f"Quick exit enabled with max_matches: {max_matches}")

    if 'sources' in connections:
        sources_config = connections['sources']
        s3_config = sources_config.get('s3')

        if s3_config:
            for key, config in s3_config.items():
                access_key = config.get('access_key')
                secret_key = config.get('secret_key')
                bucket_name = config.get('bucket_name')
                exclude_patterns = config.get(key, {}).get('exclude_patterns', [])

                system.print_info(args, f"Checking S3 profile: '{key}' with bucket '{bucket_name}'")
                profile_name = key
                if access_key and secret_key and bucket_name:
                    bucket = connect_s3(args, access_key, secret_key, bucket_name)
                    if bucket:
                        for obj in bucket.objects.all():
                            if quick_exit and len(results) >= max_matches:
                                system.print_info(args, f"Quick exit: Found {max_matches} matches, exiting...")
                                break
                            
                            remote_etag = obj.e_tag.replace('"', '')
                            system.print_debug(args, f"Remote etag: {remote_etag}")
                            file_name = obj.key
                            if system.should_exclude_file(args, file_name, exclude_patterns):
                                continue

                            file_path = f"data/s3/{remote_etag}-{file_name}"
                            os.makedirs(os.path.dirname(file_path), exist_ok=True)
                            if config.get("cache") == True:
                                if os.path.exists(file_path):
                                    shouldDownload = False
                                    local_etag = file_path.split('/')[-1].split('-')[0]
                                    system.print_debug(args, f"Local etag: {local_etag}")
                                    system.print_debug(args, f"File already exists in cache, using it. You can disable cache by setting 'cache: false' in connection.yml")
                                    if remote_etag != local_etag:
                                        system.print_debug(args, f"File in S3 bucket has changed, downloading it again...")
                                        shouldDownload = True
                                    else:
                                        shouldDownload = False

                            if shouldDownload:
                                file_path = f"data/s3/{remote_etag}-{file_name}"
                                system.print_debug(args, f"Downloading file: {file_name} to {file_path}...")
                                bucket.download_file(file_name, file_path)
                            
                            matches = system.read_match_strings(args, file_path, 'google_cloud_storage')
                            if matches:
                                for match in matches:
                                    results.append({
                                        'bucket': bucket_name,
                                        'file_path': file_name,
                                        'pattern_name': match['pattern_name'],
                                        'matches': match['matches'],
                                        'sample_text': match['sample_text'],
                                        'profile': key,
                                        'data_source': 's3'
                                    })

                    else:
                        system.print_error(args, f"Failed to connect to S3 bucket: {bucket_name}")
                else:
                    system.print_error(args, f"Incomplete S3 configuration for key: {key}")
            if config.get("cache") == False:
                os.system("rm -rf data/s3")
        else:
            system.print_error(args, "No S3 connection details found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")
    return results
