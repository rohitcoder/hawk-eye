import sys, os, time
import json
import importlib
import argparse
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown

from hawk_scanner.internals import system
from rich import print
from rich.panel import Panel
from rich.text import Text

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


clear_screen()
system.print_banner()

console = Console()

def load_command_module(command):
    try:
        module = importlib.import_module(f"hawk_scanner.commands.{command}")
        return module
    except Exception as e:
        print(f"Command '{command}' is not supported. {e} ")
        sys.exit(1)


def execute_command(command, args):
    final_results = []
    module = load_command_module(command)
    results = module.execute(args)
    for result in results:
        final_results.append(result)
    return final_results


def main():
    ## Now separate the results by data_source
    data_sources = ['s3', 'mysql', 'redis', 'firebase', 'gcs', 'fs']

    parser = argparse.ArgumentParser(description='CLI Command Executor')
    parser.add_argument('command', nargs='?', choices=data_sources, help='Command to execute')
    parser.add_argument('--json', help='Save output to json file')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args, extra_args = parser.parse_known_args()
    results = []
    if args.command:
        for data in execute_command(args.command, extra_args):
            results.append(data)
    else:
        commands = data_sources
        for command in commands:
            for data in execute_command(command, extra_args):
                results.append(data)

    ## GROUP results in grouped_results by datasource by key val
    grouped_results = {}
    for result in results:
        data_source = result['data_source']
        if data_source not in grouped_results:
            grouped_results[data_source] = []
        grouped_results[data_source].append(result)
    
    if args.json:
        with open(args.json, 'w') as file:
            file.write(json.dumps(grouped_results, indent=4))
        system.print_success(f"Results saved to {args.json}")
        sys.exit(0)
    panel = Panel(Text("Now, lets look at findings!", justify="center"))
    print(panel)


    for group in grouped_results:
        table = Table(show_header=True, header_style="bold magenta", show_lines=True, title=f"[bold blue]Total {grouped_results[group].__len__()} findings in {group}[/bold blue]")
        table.add_column("Sl. No.")
        table.add_column("Vulnerable Profile")
        if group == 's3':
            table.add_column("Bucket > File Path")
        elif group == 'mysql':
            table.add_column("Host > Database > Table.Column")
        elif group == 'redis':
            table.add_column("Host > Key")
        elif group == 'firebase' or group == 'gcs':
            table.add_column("Bucket > File Path")
        elif group == 'fs':
            table.add_column("File Path")

        table.add_column("Pattern Name")
        table.add_column("Total Exposed")
        table.add_column("Exposed Values")
        table.add_column("Sample Text")
        i = 1

        for result in grouped_results[group]:
            if group == 's3':
                table.add_row(
                    str(i),
                    result['profile'],
                    f"{result['bucket']} > {result['file_path']}",
                    result['pattern_name'],
                    str(len(result['matches'])),
                    str(', '.join(result['matches'])),
                    result['sample_text'],
                )
                AlertMsg = """
                *** PII Or Secret Found ***
                Data Source: S3 Bucket
                Bucket: {bucket}
                File Path: {file_path}
                Pattern Name: {pattern_name}
                Total Exposed: {total_exposed}
                Exposed Values: {exposed_values}
                """.format(
                    bucket=result['bucket'],
                    file_path=result['file_path'],
                    pattern_name=result['pattern_name'],
                    total_exposed=str(len(result['matches'])),
                    exposed_values=', '.join(result['matches'])
                )
                
                system.SlackNotify(AlertMsg)
                
            elif group == 'mysql':
                table.add_row(
                    str(i),
                    result['profile'],
                    f"{result['host']} > {result['database']} > {result['table']}.{result['column']}",
                    result['pattern_name'],
                    str(len(result['matches'])),
                    str(', '.join(result['matches'])),
                    result['sample_text'],
                )
                
                # Slack notification for MySQL
                AlertMsg = """
                *** PII Or Secret Found ***
                Data Source: MySQL
                Host: {host}
                Database: {database}
                Table: {table}
                Column: {column}
                Pattern Name: {pattern_name}
                Total Exposed: {total_exposed}
                Exposed Values: {exposed_values}
                """.format(
                    host=result['host'],
                    database=result['database'],
                    table=result['table'],
                    column=result['column'],
                    pattern_name=result['pattern_name'],
                    total_exposed=str(len(result['matches'])),
                    exposed_values=', '.join(result['matches'])
                )
                
                system.SlackNotify(AlertMsg)
                
            elif group == 'redis':
                table.add_row(
                    str(i),
                    result['profile'],
                    f"{result['host']} > {result['key']}",
                    result['pattern_name'],
                    str(len(result['matches'])),
                    str(', '.join(result['matches'])),
                    result['sample_text'],
                )
                AlertMsg = """
                *** PII Or Secret Found ***
                Data Source: Redis
                Host: {host}
                Key: {key}
                Pattern Name: {pattern_name}
                Total Exposed: {total_exposed}
                Exposed Values: {exposed_values}
                """.format(
                    host=result['host'],
                    key=result['key'],
                    pattern_name=result['pattern_name'],
                    total_exposed=str(len(result['matches'])),
                    exposed_values=', '.join(result['matches'])
                )
                
                system.SlackNotify(AlertMsg)
            elif group == 'firebase' or group == 'gcs':
                table.add_row(
                    str(i),
                    result['profile'],
                    f"{result['bucket']} > {result['file_path']}",
                    result['pattern_name'],
                    str(len(result['matches'])),
                    str(', '.join(result['matches'])),
                    result['sample_text'],
                )
                
                # Slack notification for Firebase/GCS
                AlertMsg = """
                *** PII Or Secret Found ***
                Data Source: Firebase/GCS
                Bucket: {bucket}
                File Path: {file_path}
                Pattern Name: {pattern_name}
                Total Exposed: {total_exposed}
                Exposed Values: {exposed_values}
                """.format(
                    bucket=result['bucket'],
                    file_path=result['file_path'],
                    pattern_name=result['pattern_name'],
                    total_exposed=str(len(result['matches'])),
                    exposed_values=', '.join(result['matches'])
                )
                
                system.SlackNotify(AlertMsg)
                
            elif group == 'fs':
                table.add_row(
                    str(i),
                    result['profile'],
                    f"{result['file_path']}",
                    result['pattern_name'],
                    str(len(result['matches'])),
                    str(', '.join(result['matches'])),
                    result['sample_text'],
                )
                AlertMsg = """
                *** PII Or Secret Found ***
                Data Source: File System
                File Path: {file_path}
                Pattern Name: {pattern_name}
                Total Exposed: {total_exposed}
                Exposed Values: {exposed_values}
                """.format(
                    file_path=result['file_path'],
                    pattern_name=result['pattern_name'],
                    total_exposed=str(len(result['matches'])),
                    exposed_values=str(', '.join(result['matches']))
                )
                
                system.SlackNotify(AlertMsg)
            else:
                # Handle other cases or do nothing for unsupported groups
                pass

            i += 1
        console.print(table)


if __name__ == '__main__':
    main()
