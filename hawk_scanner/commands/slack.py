import re
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from hawk_scanner.internals import system
from rich.console import Console

console = Console()

def connect_slack(token):
    try:
        client = WebClient(token=token)
        # Test the connection by making an API call
        response = client.auth_test()
        if response["ok"]:
            system.print_info("Connected to Slack")
            return client
        else:
            system.print_error("Failed to authenticate with Slack")
            return None
    except SlackApiError as e:
        system.print_error(f"Failed to connect to Slack with error: {e.response['error']}")
        return None

def check_slack_messages(client, patterns, profile_name, channel_types, channel_names=None):
    results = []
    try:
        team_info = client.team_info()
        workspace_url = team_info["team"]["url"].rstrip('/')
        # Get all channels of specified types
        channels = client.conversations_list(types=channel_types)["channels"]

        # Filter channels by names if provided
        if channel_names:
            channels = [channel for channel in channels if channel['name'] in channel_names]
        
        system.print_info(f"Found {len(channels)} channels of type {channel_types}")
        system.print_info(f"Checking messages in channels: {', '.join([channel['name'] for channel in channels])}")
        
        for channel in channels:
            channel_name = channel["name"]
            channel_id = channel["id"]

            # Get messages from the channel
            system.print_info(f"Checking messages in channel {channel_name} ({channel_id})")
            messages = client.conversations_history(channel=channel_id)["messages"]

            for message in messages:
                user = message.get("user", "")
                text = message.get("text")
                if text:
                    matches = system.match_strings(text)
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
                                'message_link': workspace_url + f"/archives/{channel_id}/p{message['ts'].replace('.', '')}",
                                'data_source': 'slack'
                            })
        return results
    except SlackApiError as e:
        system.print_error(f"Failed to fetch messages from Slack with error: {e.response['error']}")
        return results

def execute(args, programmatic=False):
    try:
        results = []
        system.print_info("Running Checks for Slack Sources")
        connections = system.get_connection(args, programmatic)

        if 'sources' in connections:
            sources_config = connections['sources']
            slack_config = sources_config.get('slack')

            if slack_config:
                patterns = system.get_fingerprint_file(args, programmatic)

                for key, config in slack_config.items():
                    token = config.get('token')
                    channel_types = config.get('channel_types', "public_channel,private_channel")
                    channel_names = config.get('channel_names', None)

                    if token:
                        system.print_info(f"Checking Slack Profile {key}")
                    else:
                        system.print_error(f"Incomplete Slack configuration for key: {key}")
                        continue

                    client = connect_slack(token)
                    if client:
                        results += check_slack_messages(client, patterns, key, channel_types, channel_names)
            else:
                system.print_error("No Slack connection details found in connection.yml")
        else:
            system.print_error("No 'sources' section found in connection.yml")
    except Exception as e:
        system.print_error(f"Failed to run Slack checks with error: {e}")
    return results