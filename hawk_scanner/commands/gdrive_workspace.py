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

def download_file(args, drive, file_obj, base_path):
    print(f"Downloading file: {file_obj['name']} to {base_path}")
    try:
        file_name = file_obj['name']
        file_id = file_obj['id']

        folder_path = base_path

        # Handle parents (folders)
        if 'parents' in file_obj:
            for parent_id in file_obj['parents']:
                parent_folder = drive.files().get(fileId=parent_id).execute()
                parent_folder_name = parent_folder['name']
                
                # Update folder_path to include the parent folder
                folder_path = os.path.join(folder_path, parent_folder_name)

        # Update folder_path to include the current file's name
        folder_path = os.path.join(folder_path, file_name)

        if 'mimeType' in file_obj and file_obj['mimeType'] == 'application/vnd.google-apps.folder':
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            folder_files = drive.files().list(q=f"'{file_id}' in parents").execute().get('files', [])
            for folder_file in folder_files:
                download_file(args, drive, folder_file, folder_path)
        else:
            try:
                # Check if the file is a Google Docs type
                if 'application/vnd.google-apps' in file_obj.get('mimeType', ''):
                    # For Google Docs Editors files, use export instead of GetMedia
                    response = drive.files().export(fileId=file_id, mimeType='application/pdf').execute()
                    with open(folder_path, 'wb') as f:
                        f.write(response)
                else:
                    # For other file types, use GetMedia
                    content = drive.files().get_media(fileId=file_id).execute()
                    with open(folder_path, 'wb') as f:
                        f.write(content)
            except Exception as e:
                print(f"Failed to write file: {e}")

        system.print_debug(args, f"File downloaded to: {folder_path}")
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
    connections = system.get_connection(args)
    is_cache_enabled = False

    if 'sources' in connections:
        sources_config = connections['sources']
        drive_config = sources_config.get('gdrive_workspace')
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")

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
                        
                        if 'mimeType' in file_obj and file_obj['mimeType'] == 'application/vnd.google-apps.document' or file_obj['mimeType'] == 'application/vnd.google-apps.spreadsheet' or file_obj['mimeType'] == 'application/vnd.google-apps.presentation' or file_obj['mimeType'] == 'application/vnd.google-apps.drawing' or file_obj['mimeType'] == 'application/vnd.google-apps.script':
                            file_obj['name'] = file_obj['name'] + '-runtime.pdf'

                        file_id = file_obj['id']
                        file_name = file_obj['name']
                        folder_path = "data/google_drive"

                        file_path = os.path.join(folder_path, file_name)

                        if system.should_exclude_file(args, file_name, exclude_patterns):
                            continue

                        if config.get("cache") and os.path.exists(file_path):
                            is_cache_enabled = False
                            system.print_debug(args, f"File already exists in cache, using it.")
                        else:
                            is_cache_enabled = True

                        if is_cache_enabled:
                            download_file(args, drive, file_obj, "data/google_drive/")

                        matches = system.read_match_strings(args, file_path, 'gdrive_workspace')
                        file_name = file_name.replace('-runtime.pdf', '')
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
                    system.print_error(args, "Failed to connect to Google Drive")
    else:
        system.print_error(args, "No Google Drive connection details found in connection file")

    """if not is_cache_enabled:
        os.system("rm -rf data/google_drive")"""

    return results

# Call the execute function with the necessary arguments
# execute(y
