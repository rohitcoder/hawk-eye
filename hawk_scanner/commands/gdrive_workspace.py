import os
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from hawk_scanner.internals import system

def connect_google_drive(credentials_file, impersonate_user=None):
    credentials_json = open(credentials_file, 'r').read()
    credentials_json = json.loads(credentials_json)
    credentials = service_account.Credentials.from_service_account_file(
        credentials_file,
        scopes=['https://www.googleapis.com/auth/drive.readonly'],
    )

    if impersonate_user:
        delegated_credentials = credentials.with_subject(impersonate_user)
        credentials = delegated_credentials

    try:
        drive_service = build('drive', 'v3', credentials=credentials)
        return drive_service
    except Exception as e:
        print(f"Failed to connect to Google Drive: {e}")

def download_file(drive, file_obj, base_path):
    try:
        file_name = file_obj['name']
        file_id = file_obj['id']

        folder_path = base_path
        if 'parents' in file_obj:
            for parent_id in file_obj['parents']:
                parent_folder = drive.files().get(fileId=parent_id).execute()
                if parent_folder['name'] == 'My Drive':
                    continue
                folder_path = os.path.join(folder_path, parent_folder['name'])

        file_path = os.path.join(folder_path, file_name)

        if 'mimeType' in file_obj and file_obj['mimeType'] == 'application/vnd.google-apps.folder':
            if not os.path.exists(file_path):
                os.makedirs(file_path)
            folder_files = drive.files().list(q=f"'{file_id}' in parents").execute().get('files', [])
            for folder_file in folder_files:
                download_file(drive, folder_file, folder_path)
        else:
            download_url = drive.files().get_media(fileId=file_id).execute()
            with open(file_path, 'wb') as fh:
                fh.write(download_url)

        system.print_debug(f"File downloaded to: {file_path}")
    except Exception as e:
        print(f"Failed to download file: {e}")

def list_files(drive, impersonate_user=None):
    try:
        query = "'root' in parents"
        if impersonate_user:
            query += f" and '{impersonate_user}' in owners"
        file_list = drive.files().list(q=query).execute().get('files', [])
        return file_list
    except Exception as e:
        print(f"Error listing files: {e}")
        return []

def execute(args):
    results = []
    connections = system.get_connection()
    is_cache_enabled = False

    if 'sources' in connections:
        sources_config = connections['sources']
        drive_config = sources_config.get('gdrive_workspace')
    else:
        system.print_error("No 'sources' section found in connection.yml")

    if drive_config:
        for key, config in drive_config.items():
            credentials_file = config.get('credentials_file')
            impersonate_users = config.get('impersonate_users', [])
            exclude_patterns = config.get(key, {}).get('exclude_patterns', [])
            is_cache_enabled = config.get('cache', False)

            for impersonate_user in impersonate_users or [None]:
                drive = connect_google_drive(credentials_file, impersonate_user)
                if not os.path.exists("data/google_drive"):
                    os.makedirs("data/google_drive")
                if drive:
                    files = list_files(drive, impersonate_user)
                    for file_obj in files:
                        download_file(drive, file_obj, "data/google_drive")
                        file_id = file_obj['id']
                        file_name = file_obj['name']
                        if 'mimeType' in file_obj and file_obj['mimeType'] == 'application/vnd.google-apps.folder':
                            continue

                        parent_folder_ids = file_obj.get('parents', [])
                        folder_path = "data/google_drive"
                        if parent_folder_ids:
                            for parent_id in parent_folder_ids:
                                parent_folder = drive.files().get(fileId=parent_id).execute()
                                if parent_folder['name'] == 'My Drive':
                                    continue
                                folder_path = os.path.join(folder_path, parent_folder['name'])

                        file_path = os.path.join(folder_path, file_name)

                        if system.should_exclude_file(file_name, exclude_patterns):
                            continue

                        if config.get("cache") and os.path.exists(file_path):
                            is_cache_enabled = False
                            system.print_debug(f"File already exists in cache, using it.")
                        else:
                            is_cache_enabled = True

                        if is_cache_enabled:
                            download_file(drive, file_obj, "data/google_drive")

                        matches = system.read_match_strings(file_path, 'gdrive')
                        if matches:
                            for match in matches:
                                results.append({
                                    'file_id': file_id,
                                    'file_name': file_name,
                                    'user': impersonate_user,
                                    'file_path': file_path,
                                    'pattern_name': match['pattern_name'],
                                    'matches': match['matches'],
                                    'sample_text': match['sample_text'],
                                    'profile': key,
                                    'data_source': 'gdrive_workspace'
                                })
                else:
                    system.print_error("Failed to connect to Google Drive")
    else:
        system.print_error("No Google Drive connection details found in connection file")

    if not is_cache_enabled:
        os.system("rm -rf data/google_drive")

    return results

# Call the execute function with the necessary arguments
# execute(y
