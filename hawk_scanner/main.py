import sys
import os
import json
import yaml
import importlib
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from collections import defaultdict
from hawk_scanner.internals import system
from rich import print
import ssl

# Disable SSL verification globally
ssl._create_default_https_context = ssl._create_unverified_context

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


clear_screen()

console = Console()

def load_command_module(command):
    try:
        module = importlib.import_module(f"hawk_scanner.commands.{command}")
        return module
    except Exception as e:
        print(f"Command '{command}' is not supported. {e}")
        sys.exit(1)


def execute_command(command, args):
    module = load_command_module(command)
    return module.execute(args)


def group_results(args, results):
    grouped_results = defaultdict(list)
    for result in results:
        connection = system.get_connection(args)
        result = system.evaluate_severity(result, connection)
        grouped_results[result['data_source']].append(result)
    return grouped_results


def format_slack_message(group, result, records_mini):
    template_map = {
        's3': """
        *** PII Or Secret Found ***
        Data Source: S3 Bucket - {vulnerable_profile}
        Bucket: {bucket}
        File Path: {file_path}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'mysql': """
        *** PII Or Secret Found ***
        Data Source: MySQL - {vulnerable_profile}
        Host: {host}
        Database: {database}
        Table: {table}
        Column: {column}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'postgresql': """
        *** PII Or Secret Found ***
        Data Source: PostgreSQL - {vulnerable_profile}
        Host: {host}
        Database: {database}
        Table: {table}
        Column: {column}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'mongodb': """
        *** PII Or Secret Found ***
        Data Source: MongoDB - {vulnerable_profile}
        Host: {host}
        Database: {database}
        Collection: {collection}
        Field: {field}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'redis': """
        *** PII Or Secret Found ***
        Data Source: Redis - {vulnerable_profile}
        Host: {host}
        Key: {key}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'firebase': """
        *** PII Or Secret Found ***
        Data Source: Firebase - {vulnerable_profile}
        Bucket: {bucket}
        File Path: {file_path}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'gcs': """
        *** PII Or Secret Found ***
        Data Source: GCS - {vulnerable_profile}
        Bucket: {bucket}
        File Path: {file_path}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'fs': """
        *** PII Or Secret Found ***
        Data Source: File System - {vulnerable_profile}
        File Path: {file_path}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'slack': """
        *** PII Or Secret Found ***
        Data Source: Slack - {vulnerable_profile}
        Channel Name: {channel_name}
        Message Link: {message_link}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'couchdb': """
        *** PII Or Secret Found ***
        Data Source: CouchDB - {vulnerable_profile}
        Host: {host}
        Database: {database}
        Document ID: {doc_id}
        Field: {field}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'gdrive': """
        *** PII Or Secret Found ***
        Data Source: Google Drive - {vulnerable_profile}
        File Name: {file_name}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'gdrive_workspace': """
        *** PII Or Secret Found ***
        Data Source: Google Drive Workspace - {vulnerable_profile}
        File Name: {file_name}
        User: {user}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """,
        'text': """
        *** PII Or Secret Found ***
        Data Source: Text - {vulnerable_profile}
        Pattern Name: {pattern_name}
        Total Exposed: {total_exposed}
        Exposed Values: {exposed_values}
        """
    }
    return template_map.get(group, "").format(
        vulnerable_profile=result['profile'],
        bucket=result.get('bucket', ''),
        file_path=result.get('file_path', ''),
        host=result.get('host', ''),
        database=result.get('database', ''),
        table=result.get('table', ''),
        column=result.get('column', ''),
        doc_id=result.get('doc_id', ''),
        channel_name=result.get('channel_name', ''),
        message_link=result.get('message_link', ''),
        file_name=result.get('file_name', ''),
        user=result.get('user', ''),
        pattern_name=result['pattern_name'],
        total_exposed=str(len(result['matches'])),
        exposed_values=records_mini
    )


def add_columns_to_table(group, table):
    if group in ['s3', 'firebase', 'gcs']:
        table.add_column("Bucket > File Path")
    elif group in ['mysql', 'postgresql']:
        table.add_column("Host > Database > Table.Column")
    elif group == 'redis':
        table.add_column("Host > Key")
    elif group == 'mongodb':
        table.add_column("Host > Database > Collection > Field")
    elif group == 'slack':
        table.add_column("Channel Name > Message Link")
    elif group == 'gdrive':
        table.add_column("File Name")
    elif group == 'gdrive_workspace':
        table.add_column("File Name")
        table.add_column("User")
    elif group == 'couchdb':
        table.add_column("Host > Database > Document ID > Field")
    elif group == 'fs':
        table.add_column("File Path")
    table.add_column("Pattern Name")
    table.add_column("Total Exposed")
    table.add_column("Exposed Values")
    table.add_column("Sample Text")


def main():
    start_time = time.time()

    args = system.parse_args()
    system.print_banner(args)
    results = []
    
    if args.command:
        connections = system.get_connection(args)
        data_sources = connections.get('sources', {}).keys()
        commands = [args.command] if args.command != 'all' else data_sources
        for command in commands:
            results.extend(execute_command(command, args))
    else:
        system.print_error(args, "Please provide a command to execute")
        sys.exit(1)

    grouped_results = group_results(args, results)
    if args.json:
        if args.json:
            with open(args.json, 'w') as file:
                file.write(json.dumps(grouped_results, indent=4))
            system.print_success(args, f"Results saved to {args.json}")
        else:
            print(json.dumps(grouped_results, indent=4))
        sys.exit(0)

    if args.stdout:
        print(json.dumps(grouped_results, indent=4))
        sys.exit(0)

    # Display results in the table format
    console.print(Panel(Text("Now, let's look at findings!", justify="center")))

    for group, group_data in grouped_results.items():
        table = Table(show_header=True, header_style="bold magenta", show_lines=True, 
                      title=f"[bold blue]Total {len(group_data)} findings in {group}[/bold blue]")
        table.add_column("Sl. No.")
        table.add_column("Vulnerable Profile")
        add_columns_to_table(group, table)
        for i, result in enumerate(group_data, 1):
            records_mini = ', '.join(result['matches']) if len(result['matches']) < 25 else ', '.join(result['matches'][:25]) + f" + {len(result['matches']) - 25} more"
            slack_message = format_slack_message(group, result, records_mini)
            if slack_message:
                system.create_jira_ticket(args, result, slack_message)
                system.SlackNotify(slack_message, args)

            if group == 's3':
                table.add_row(str(i), result['profile'], f"{result['bucket']} > {result['file_path']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group in ['mysql', 'postgresql']:
                table.add_row(str(i), result['profile'],
                              f"{result['host']} > {result['database']} > {result['table']}.{result['column']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'mongodb':
                table.add_row(str(i), result['profile'],
                              f"{result['host']} > {result['database']} > {result['collection']} > {result['field']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'slack':
                table.add_row(str(i), result['profile'],
                              f"{result['channel_name']} > {result['message_link']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'redis':
                table.add_row(str(i), result['profile'], f"{result['host']} > {result['key']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group in ['firebase', 'gcs']:
                table.add_row(str(i), result['profile'], f"{result['bucket']} > {result['file_path']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'fs':
                table.add_row(str(i), result['profile'], result['file_path'], result['pattern_name'],
                              str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'couchdb':
                table.add_row(str(i), result['profile'],
                              f"{result['host']} > {result['database']} > {result['doc_id']} > {result['field']}",
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'gdrive':
                table.add_row(str(i), result['profile'], result['file_name'], result['pattern_name'],
                              str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'gdrive_workspace':
                table.add_row(str(i), result['profile'], result['file_name'], result['user'],
                              result['pattern_name'], str(len(result['matches'])), records_mini, result['sample_text'])
            elif group == 'text':
                table.add_row(str(i), result['profile'], result['pattern_name'],
                              str(len(result['matches'])), records_mini, result['sample_text'])

        console.print(table)

    if args.hawk_thuu:
        console.print("Hawk thuuu, Spitting on that thang!....")
        os.system("rm -rf data/*")
        time.sleep(2)
        console.print("Cleaned hawk data! 🧹")

    # Measure and print the total execution time
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"[bold green]Execution completed in {execution_time:.2f} seconds.[/bold green]")


if __name__ == '__main__':
    main()
