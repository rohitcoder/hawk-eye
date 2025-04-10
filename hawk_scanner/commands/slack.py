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

def check_slack_messages(args, client, patterns, profile_name, channel_types, isExternal, read_from, channel_ids=None, limit_mins=60, archived_channels=False, onlyArchived=False, blacklisted_channel_ids=None):
    
    results = []

    # Initalize blacklisted_channel_ids if not provided
    if blacklisted_channel_ids is None:
        blacklisted_channel_ids = []
        
    try:
        connection = system.get_connection(args)
        options = connection.get('options', {})
        quick_exit = options.get('quick_exit', False)
        max_matches = None
        if quick_exit:
            max_matches = options.get('max_matches', 1)
            system.print_info(args, f"Quick exit enabled with max_matches: {max_matches}")

        team_info = client.team_info()
        workspace_url = team_info["team"]["url"].rstrip('/')
            
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
            system.print_info(args, f"Active blacklist: {blacklisted_channel_ids}")

            # Pagination logic to fetch all non-archived channels
            cursor = None
            while True:
                try:
                    response = rate_limit_retry(
                        client.conversations_list,
                        types=channel_types,
                        limit=1000,
                        cursor=cursor,
                        exclude_archived=not archived_channels
                        )
                    
                    # Filter blacklisted channels immediately
                    batch_channels = response.get("channels", [])
                    filtered_batch = [
                        ch for ch in batch_channels 
                        if ch['id'] not in blacklisted_channel_ids
                    ]

                    # Log filtering results
                    system.print_debug(args, 
                        f"Batch: {len(batch_channels)} channels before filtering, "
                        f"{len(filtered_batch)} after blacklist")

                    if onlyArchived:
                        archived_channels = True
                    if archived_channels:
                        system.print_debug(args, f"Considering archived channels, you may want to set archived_channels to False")
                    else:
                        system.print_debug(args, f"Skipping archived channels, you may want to set archived_channels to True")


                    if onlyArchived:
                        system.print_info(args, "Getting only archived channels....")
                        channels.extend([ch for ch in batch_channels if ch.get("is_archived")])
                    else:
                        channels.extend(filtered_batch)
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
                if channel_id in blacklisted_channel_ids:
                    system.print_debug(args, f"Skipping blacklisted channel: {channel_id}")
                    continue
                try:
                    channel = rate_limit_retry(client.conversations_info, channel=channel_id)["channel"]
                    if archived_channels or not channel.get("is_archived"):
                        channels.append(channel)
                    else:
                        system.print_debug(args, f"Skipping archived channel: {channel_id}")
                except SlackApiError as e:
                    system.print_error(args, f"Failed to fetch channel with id {channel_id} with error: {e.response['error']}")
        system.print_info(args, f"Found {len(channels)} channels")

        filtered_channels = []
        for channel in channels:
            channel_is_external = channel.get("is_ext_shared")
            
            if isExternal is not None:
                if isExternal and not channel_is_external:
                    system.print_debug(args, f"Skipping non-external channel: {channel['name']}")
                    continue  # Skip this channel
                elif not isExternal and channel_is_external:
                    system.print_debug(args, f"Skipping external channel: {channel['name']}")
                    continue  # Skip this channel

            if isExternal and channel_is_external:
                system.print_info(args, f"Found external channel: {channel['name']}")

            filtered_channels.append(channel)  # Add the channel if it wasn't skipped
        if filtered_channels.__len__() > 0:
            channels = filtered_channels  # Update the original list
        # Optional: Print or log the total number of channels fetched
        system.print_info(args, f"Total channels to scan after filteration: {len(channels)}")
        system.print_info(args, f"Found {len(channels)} channels of type {channel_types}")
        system.print_debug(args, f"Checking messages in channels: {', '.join([channel['name'] for channel in channels])}")

        for channel in channels:
            total_results = 0
            channel_name = channel["name"]
            channel_id = channel["id"]
            latest_time = int(time.time())

            if read_from == 'last_message':
                system.print_info(args, "Fetching messages from the last message in the channel " + channel_name)
                last_msg = get_last_msg(args, client, channel_id)
                if last_msg:
                    latest_time = float(last_msg['timestamp'])
                    # Add 1 second to the latest time to get latest message along with it
                    latest_time += 1
            elif read_from:
                try:
                    read_from = int(read_from)
                    latest_time = read_from
                    # Add 1 second to the latest time to get latest message along with it
                    latest_time += 1
                except ValueError:
                    system.print_error(args, "Invalid value for read_from in Slack configuration. It should be either 'last_message' or a valid Unix timestamp")
                    exit(1)
            else:
                latest_time = int(time.time())
            oldest_time = latest_time - (limit_mins * 60)
            # Get messages from the channel within the time range
            system.print_info(args, f"Checking messages in channel {channel_name} ({channel_id})")
            system.print_info(args, f"Fetching messages from {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(oldest_time))} to {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(latest_time))}")
            messages = []
            cursor = None  # Start without a cursor

            while True:
                response = rate_limit_retry(client.conversations_history, 
                                            channel=channel_id, 
                                            oldest=oldest_time, 
                                            latest=latest_time,
                                            limit=200,
                                            cursor=cursor)  

                messages.extend(response.get("messages", []))

                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:  
                    break  # Stop if there's no more data

            system.print_debug(args, f"Fetched {len(messages)} messages from {channel_name} ({channel_id})")
            for message in messages:
                if quick_exit and total_results >= max_matches:
                    system.print_info(args, f"Quick exit enabled. Found {max_matches} matches. Exiting...")
                    break
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
                                total_results += 1
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
                            total_results += 1
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
                                            total_results += 1
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
                                        total_results += 1
                                        results.append({
                                            'channel_id': channel_id,
                                            'channel_name': channel_name,
                                            'user': reply_user,
                                            'pattern_name': match['pattern_name'],
                                            'matches': list(set(match['matches'])),
                                            'sample_text': match['sample_text'],
                                            'profile': profile_name,
                                            'message_link': workspace_url + f"/archives/{channel_id}/p{reply_ts.replace('.', '')}?thread_ts={thread_ts}&cid={channel_id}",
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

def get_last_msg(args, client, channel_id):
    """
    Fetches the last message from the specified Slack channel.
    Handles rate limits and retries if necessary.
    """
    try:
        def rate_limit_retry(func, *args, **kwargs):
            while True:
                try:
                    return func(*args, **kwargs)
                except SlackApiError as e:
                    if e.response["error"] == "ratelimited":
                        retry_after = int(e.response.headers.get("Retry-After", 1))
                        system.print_info(args, f"Rate limited. Retrying after {retry_after} seconds...")
                        time.sleep(retry_after)
                    else:
                        raise
        
        system.print_info(args, f"Fetching last message from channel {channel_id}")
        response = rate_limit_retry(client.conversations_history, channel=channel_id, limit=1)
        messages = response.get("messages", [])
        
        if messages:
            last_message = messages[0]  # Get the latest message
            return {
                'user': last_message.get("user", "Unknown"),
                'text': last_message.get("text", ""),
                'timestamp': last_message.get("ts", ""),
                'message_link': f"https://slack.com/archives/{channel_id}/p{last_message.get('ts', '').replace('.', '')}",
            }
        else:
            system.print_info(args, f"No messages found in channel {channel_id}")
            return None
    
    except SlackApiError as e:
        system.print_error(args, f"Failed to fetch last message from channel {channel_id} with error: {e.response['error']}")
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
                current_unix_timestamp = int(time.time())
                read_from = config.get('read_from', current_unix_timestamp)
                token = config.get('token')
                channel_types = config.get('channel_types', "public_channel,private_channel")
                channel_ids = config.get('channel_ids', [])
                blacklisted_channel_ids = config.get('blacklisted_channel_ids', [])
                limit_mins = config.get('limit_mins', 60)
                isExternal = config.get('isExternal', None)
                onlyArchived = config.get('onlyArchived', False)
                archived_channels = config.get('archived_channels', False)

                # Always apply blacklist, regardless of channel_ids
                if blacklisted_channel_ids:
                    system.print_info(args, f"Filtering out blacklisted channels from {blacklisted_channel_ids}")
                    # If specific channels are specified, filter them
                    if channel_ids:
                        original_count = len(channel_ids)
                        channel_ids = [
                            cid for cid in channel_ids 
                            if cid not in blacklisted_channel_ids
                        ]
                        removed = original_count - len(channel_ids)
                        system.print_info(args,
                            f"Filtered {removed} blacklisted channels from explicit list. "
                            f"Remaining: {channel_ids}")


                # Filter out blacklisted channels, If specific channels are specified
                if channel_ids:
                    system.print_info(args, f"Filtering out blacklisted channels from {channel_ids}")
                    channel_ids = [channel_id for channel_id in channel_ids if channel_id not in blacklisted_channel_ids]
                    system.print_info(args, f"Filtered channel IDs after blacklist removal: {channel_ids}")
    
                if token:
                    system.print_info(args, f"Checking Slack Profile {key}")
                else:
                    system.print_error(args, f"Incomplete Slack configuration for key: {key}")
                    continue

                client = connect_slack(args, token)
                if client:
                    results += check_slack_messages(args, client, patterns, key, channel_types, isExternal, read_from, channel_ids, limit_mins, archived_channels, onlyArchived, blacklisted_channel_ids)
        else:
            system.print_error(args, "No Slack connection details found in connection.yml")
    else:
        system.print_error(args, "No 'sources' section found in connection.yml")

    return results
