import time, os, requests
from datetime import datetime
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def connect_slack(args, token):
    try:
        client = WebClient(token=token)
        # Test the connection by making an API call
        response = client.auth_test()
        if response["ok"]:
            system.print_info(args, "Connected to Slack")
            return client
        else:
            system.print_error(args, "Failed to authenticate with Slack")
            return None
    except SlackApiError as e:
        system.print_error(args, f"Failed to connect to Slack with error: {e.response['error']}")
        return None


def check_slack_messages(args, client, patterns, profile_name, channel_types, channel_ids=None, limit_mins=60, archived_channels=False):
    results = []
    try:
        team_info = client.team_info()
        workspace_url = team_info["team"]["url"].rstrip('/')

        # Get the Unix timestamp for 'limit_mins' minutes ago
        current_time = time.time()
        oldest_time = current_time - (limit_mins * 60)

        # Convert to human-readable time for debugging
        current_time_readable = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
        oldest_time_readable = datetime.fromtimestamp(oldest_time).strftime('%Y-%m-%d %H:%M:%S')

        system.print_info(args, f"Current Time: {current_time_readable}")
        system.print_info(args, f"Fetching messages from the last {limit_mins} minutes (Oldest Time: {oldest_time_readable}, Unix: {int(oldest_time)})")

        # Helper function to handle rate limits
        hawk_args = args
        def rate_limit_retry(func, *args, **kwargs):
            while True:
                try:
                    return func(*args, **kwargs)
                except SlackApiError as e:
                    if e.response["error"] == "ratelimited":
                        retry_after = int(e.response.headers.get("Retry-After", 1))
                        system.print_info(hawk_args, f"Rate limited. Retrying after {retry_after} seconds...")
                        time.sleep(retry_after)
                    else:
                        raise

        # Get all channels of specified types
        channels = []

        if not channel_ids:
            system.print_info(args, "Getting all channels because no channel_ids provided")

            # Pagination logic to fetch all non-archived channels
            cursor = None
            while True:
                try:
                    if archived_channels:
                        system.print_debug(args, f"Considering archived channels, you may want to set archived_channels to False")
                    else:
                        system.print_debug(args, f"Skipping archived channels, you may want to set archived_channels to True")

                    response = rate_limit_retry(
                        client.conversations_list,
                        types=channel_types,
                        limit=1000,
                        cursor=cursor,
                        exclude_archived=not archived_channels
                    )
                    channels.extend(response.get("channels", []))

                    # Update the cursor for the next batch
                    cursor = response.get("response_metadata", {}).get("next_cursor")

                    if not cursor:  # Break the loop if there are no more channels to fetch
                        break
                except SlackApiError as e:
                    system.print_error(args, f"Failed to fetch channels: {e.response['error']}")
                    break
        else:
            system.print_info(args, "Getting channels by channel_ids")
            for channel_id in channel_ids:
                try:
                    channel = rate_limit_retry(client.conversations_info, channel=channel_id)["channel"]
                    if archived_channels or not channel.get("is_archived"):
                        channels.append(channel)
                    else:
                        system.print_debug(args, f"Skipping archived channel: {channel_id}")
                except SlackApiError as e:
                    system.print_error(args, f"Failed to fetch channel with id {channel_id} with error: {e.response['error']}")

        # Optional: Print or log the total number of channels fetched
        system.print_info(args, f"Total channels fetched: {len(channels)}")
        system.print_info(args, f"Found {len(channels)} channels of type {channel_types}")
        system.print_debug(args, f"Checking messages in channels: {', '.join([channel['name'] for channel in channels])}")

        for channel in channels:
            channel_name = channel["name"]
            channel_id = channel["id"]

            # Get messages from the channel within the time range
            system.print_info(args, f"Checking messages in channel {channel_name} ({channel_id})")
            messages = rate_limit_retry(client.conversations_history, channel=channel_id, oldest=oldest_time)["messages"]
            for message in messages:
                user = message.get("user", "")
                text = message.get("text")
                message_ts = message.get("ts")
                files = message.get("files", [])
                for file in files:
                    folder_path = f"data/slack/"
                    file_addr = download_file(args, client, file, folder_path)
                    if file_addr:
                        system.print_debug(args, f"Checking file: {file_addr}")
                        matches = system.read_match_strings(args, file_addr, 'slack')
                        if matches:
                            for match in matches:
                                results.append({
                                    'channel_id': channel_id,
                                    'channel_name': channel_name,
                                    'user': user,
                                    'pattern_name': match['pattern_name'],
                                    'matches': list(set(match['matches'])),
                                    'sample_text': match['sample_text'],
                                    'profile': profile_name,
                                    'message_link': workspace_url + f"/archives/{channel_id}/p{message_ts.replace('.', '')}",
                                    'data_source': 'slack'
                                })

                # Check main message for matches
                if text:
                    matches = system.match_strings(args, text)
                    if matches:
                        for match in matches:
                            results.append({
                                'channel_id': channel_id,
                                'channel_name': channel_name,
                                'user': user,
                                'pattern_name': match['pattern_name'],
                                'matches': list(set(match['matches'])),
                                'sample_text': match['sample_text'],
                                'profile': profile_name,
                                'message_link': workspace_url + f"/archives/{channel_id}/p{message_ts.replace('.', '')}",
                                'data_source': 'slack'
                            })

                if "thread_ts" in message:
                    thread_ts = message["thread_ts"]
                    replies = rate_limit_retry(client.conversations_replies, channel=channel_id, ts=thread_ts, oldest=oldest_time)["messages"]
                    for reply in replies:
                        if reply["ts"] != thread_ts:  # Skip the parent message
                            reply_user = reply.get("user", "")
                            reply_text = reply.get("text")
                            reply_ts = reply.get("ts")

                            reply_files = reply.get("files", [])
                            for file in reply_files:
                                folder_path = f"data/slack/"
                                file_addr = download_file(args, client, file, folder_path)
                                if file_addr:
                                    system.print_debug(args, f"Checking file: {file_addr}")
                                    matches = system.read_match_strings(args, file_addr, 'slack')
                                    if matches:
                                        for match in matches:
                                            results.append({
                                                'channel_id': channel_id,
                                                'channel_name': channel_name,
                                                'user': reply_user,
                                                'pattern_name': match['pattern_name'],
                                                'matches': list(set(match['matches'])),
                                                'sample_text': match['sample_text'],
                                                'profile': profile_name,
                                                'message_link': workspace_url + f"/archives/{channel_id}/p{reply_ts.replace('.', '')}",
                                                'data_source': 'slack'
                                            })

                            if reply_text:
                                reply_matches = system.match_strings(args, reply_text)
                                if reply_matches:
                                    for match in reply_matches:
                                        results.append({
                                            'channel_id': channel_id,
                                            'channel_name': channel_name,
                                            'user': reply_user,
                                            'pattern_name': match['pattern_name'],
                                            'matches': list(set(match['matches'])),
                                            'sample_text': match['sample_text'],
                                            'profile': profile_name,
                                            'message_link': workspace_url + f"/archives/{channel_id}/p{reply_ts.replace('.', '')}",
                                            'data_source': 'slack'
                                        })

        return results

    except SlackApiError as e:
        system.print_error(args, f"Failed to fetch messages from Slack with error: {e}")
        return results




def download_file(args, client, file_info, folder_path) -> str:
    try:
        # Ensure the folder exists
        os.makedirs(folder_path, exist_ok=True)

        # Use the Slack client to get file info
        file_url = file_info['url_private_download']
        file_name = file_info['name']

        # Create the full path to save the file
        file_path = os.path.join(folder_path, file_name)

        # Send a GET request to download the file
        system.print_debug(args, f"Downloading file: {file_url}")
        response = requests.get(file_url, headers={f'Authorization': f"Bearer {client.token}"})
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                f.write(response.content)
            return file_path
        else:
            # Log error if the status code is not 200
            system.print_error(args, f"Failed to download file with status code: {response.status_code}")
            return None

    except SlackApiError as e:
        # Handle Slack API-specific errors
        system.print_error(args, f"Failed to download file with error: {e.response['error']}")
        return None

    except Exception as e:
        # Handle any other exceptions
        system.print_error(args, f"An unexpected error occurred: {str(e)}")
        return None


def execute(args):
    results = []
    system.print_info(args, "Running Checks for Slack Sources")
    connections = system.get_connection(args)

    if 'sources' in connections:
        sources_config = connections['sources']
        slack_config = sources_config.get('slack')

        if slack_config:
            patterns = system.get_fingerprint_file(args)

            for key, config in slack_config.items():
                token = config.get('token')
                channel_types = config.get('channel_types', "public_channel,private_channel")
                channel_ids = config.get('channel_ids', [])
                limit_mins = config.get('limit_mins', 60)
                archived_channels = config.get('archived_channels', False)

                if token:
                    system.print_info(args, f"Checking Slack Profile {key}")
                else:
                    system.print_error(args, f"Incomplete Slack configuration for key: {key}")
                    continue

                client = connect_slack(args, token)
                if client:
                    results += check_slack_messages(args, client, patterns, key, channel_types, channel_ids, limit_mins, archived_channels)
        else:
            system.print_error(args, "No Slack connection details found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")

    return results