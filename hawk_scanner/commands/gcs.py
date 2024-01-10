import argparse
from google.cloud import storage
from rich.console import Console
from hawk_scanner.internals import system
import os
import re
import time
import yaml

def connect_google_cloud(bucket_name, credentials_file):
    try:
        ## connect using credentials file
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_file
        client = storage.Client()
        bucket = client.get_bucket(bucket_name)
        system.print_debug(f"Connected to Google Cloud Storage bucket: {bucket_name}")
        return bucket
    except Exception as e:
        print(f"Failed to connect to Google Cloud Storage bucket: {e}")

def get_last_update_time(blob):
    # Use Google Cloud Blob's etag as the entity tag (ETag)
    return blob.etag

def execute(args, programmatic=False):
    try:
        results = []
        shouldDownload = True
        connections = system.get_connection(args, programmatic)
        fingerprints = system.get_fingerprint_file(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            gcs_config = sources_config.get('gcs')

            if gcs_config:
                for key, config in gcs_config.items():
                    bucket_name = config.get('bucket_name')
                    exclude_patterns = config.get(key, {}).get('exclude_patterns', [])
                    credentials_file = config.get('credentials_file')

                    if bucket_name:
                        bucket = connect_google_cloud(bucket_name, credentials_file)
                        if bucket:
                            for blob in bucket.list_blobs():
                                file_name = blob.name
                                ## get unique etag or hash of file
                                remote_etag = get_last_update_time(blob)
                                system.print_debug(f"Remote etag: {remote_etag}")

                                if system.should_exclude_file(file_name, exclude_patterns):
                                    continue

                                file_path = f"data/google_cloud_storage/{remote_etag}-{file_name}"
                                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                                if config.get("cache") == True:
                                    if os.path.exists(file_path):
                                        shouldDownload = False
                                        local_etag = file_path.split('/')[-1].split('-')[0]
                                        system.print_debug(f"Local etag: {local_etag}")
                                        system.print_debug(f"File already exists in cache, using it. You can disable cache by setting 'cache: false' in connection.yml")
                                        if remote_etag != local_etag:
                                            system.print_debug(f"File in Google Cloud Storage bucket has changed, downloading it again...")
                                            shouldDownload = True
                                        else:
                                            shouldDownload = False

                                if shouldDownload:
                                    system.print_debug(f"Downloading file: {file_name} to {file_path}...")
                                    blob.download_to_filename(file_path)

                                matches = system.analyze_file(file_path, 'google_cloud_storage', connections, fingerprints, programmatic=programmatic)
                                if matches:
                                    for match in matches:
                                        results.append({
                                            'bucket': bucket_name,
                                            'file_path': file_name,
                                            'pattern_name': match['pattern_name'],
                                            'matches': match['matches'],
                                            'sample_text': match['sample_text'],
                                            'profile': key,
                                            'data_source': 'gcs'
                                        })
                        else:
                            system.print_error(f"Failed to connect to Google Cloud Storage bucket: {bucket_name}")
                    else:
                        system.print_error(f"Incomplete Google Cloud Storage configuration for key: {key}")
            else:
                system.print_error("No Google Cloud Storage connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
        if config.get("cache") == False:
            os.system("rm -rf data/google_cloud_storage")
    except Exception as e:
        print(f"Failed to connect to Google Cloud Storage bucket: {e}")
    return results
