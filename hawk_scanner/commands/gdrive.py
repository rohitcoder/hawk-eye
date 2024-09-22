import os, json
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from rich.console import Console
from hawk_scanner.internals import system
from pydrive2.fs import GDriveFileSystem

def connect_google_drive(args, credentials_file):
    credentials = open(credentials_file, 'r').read()
    credentials = json.loads(credentials)
    ## if installed key is in the credentials file, use it
    if 'installed' in credentials:
        credentials = credentials['installed']
    client_id = credentials['client_id']
    client_secret = credentials['client_secret']

    try:
        fs = GDriveFileSystem("root", client_id=client_id, client_secret=client_secret, token=credentials_file)
        system.print_debug(args, "Connected to Google Drive")
        drive = fs.client
        return drive
    except Exception as e:
        print(f"Failed to connect to Google Drive: {e}")
    os.system("rm -rf client_secrets.json")

def download_file(args, drive, file_obj, base_path):
    try:
        file_name = file_obj['title']
        file_id = file_obj['id']

        # Get the parent folder IDs of the file
        parent_folder_ids = file_obj['parents']

        # Initialize folder_path with the base_path
        folder_path = base_path

        # If the file has parent folders, construct the destination path
        if parent_folder_ids:
            for parent_id in parent_folder_ids:
                parent_folder = drive.CreateFile({'id': parent_id['id']})
                if parent_folder['title'] == 'My Drive':
                    continue
                folder_path = os.path.join(folder_path, parent_folder['title'])

        file_path = os.path.join(folder_path, file_name)

        if file_obj['mimeType'] == 'application/vnd.google-apps.folder':
            if not os.path.exists(file_path):
                os.makedirs(file_path)
            folder_files = drive.ListFile({'q': f"'{file_id}' in parents"}).GetList()
            for folder_file in folder_files:
                download_file(drive, folder_file, folder_path)
        else:
            file_obj.GetContentFile(file_path)

        system.print_debug(args, f"File downloaded to: {file_path}")
    except Exception as e:
        print(f"Failed to download file: {e}")

def list_files(drive, folder_name=None):
    try:
        file_list = drive.ListFile({'q': f"'root' in parents and title='{folder_name}'"}).GetList() if folder_name else drive.ListFile().GetList()
        return file_list
    except Exception as e:
        print(f"Error listing files: {e}")
        return []

def execute(args):
    results = []
    should_download = True
    connections = system.get_connection(args)
    is_cache_enabled = False
    drive_config = None

    if 'sources' in connections:
        sources_config = connections['sources']
        drive_config = sources_config.get('gdrive')
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")

    if drive_config:
        for key, config in drive_config.items():
            credentials_file = config.get('credentials_file')
            folder_name = config.get('folder_name')
            exclude_patterns = config.get(key, {}).get('exclude_patterns', [])
            is_cache_enabled = config.get('cache', False)
            drive = connect_google_drive(args, credentials_file)
            if not os.path.exists("data/google_drive"):
                os.makedirs("data/google_drive")
            if drive:
                files = list_files(drive, folder_name=folder_name)
                for file_obj in files:
                    download_file(drive, file_obj, "data/google_drive")
                    file_id = file_obj['id']
                    file_name = file_obj['title']
                    if file_obj['mimeType'] == 'application/vnd.google-apps.folder':
                        continue

                    # Construct file_path with the correct folder structure
                    parent_folder_ids = file_obj['parents']
                    folder_path = "data/google_drive"
                    if parent_folder_ids:
                        for parent_id in parent_folder_ids:
                            parent_folder = drive.CreateFile({'id': parent_id['id']})
                            if parent_folder['title'] == 'My Drive':
                                continue
                            folder_path = os.path.join(folder_path, parent_folder['title'])

                    file_path = os.path.join(folder_path, file_name)

                    if system.should_exclude_file(args, file_name, exclude_patterns):
                        continue

                    if config.get("cache") and os.path.exists(file_path):
                        should_download = False
                        system.print_debug(args, f"File already exists in cache, using it.")
                    else:
                        should_download = True

                    if should_download:
                        download_file(drive, file_obj, "data/google_drive")

                    matches = system.read_match_strings(args, file_path, 'gdrive')
                    if matches:
                        for match in matches:
                            results.append({
                                'file_id': file_id,
                                'file_name': file_name,
                                'file_path': file_path,
                                'pattern_name': match['pattern_name'],
                                'matches': match['matches'],
                                'sample_text': match['sample_text'],
                                'profile': key,
                                'data_source': 'gdrive'
                            })
            else:
                system.print_error(args, "Failed to connect to Google Drive")
    else:
        system.print_error(args, "No Google Drive connection details found in connection file")

    if not is_cache_enabled:
        os.system("rm -rf data/google_drive")

    return results

# Call the execute function with the necessary arguments
# execute(your_args)
