from rich.console import Console
from rich.table import Table
import random
import yaml
import re
import os
import argparse
import requests
import json

console = Console()
parser = argparse.ArgumentParser(description='🦅 A powerful scanner to scan your Filesystem, S3, MySQL, Redis, Google Cloud Storage and Firebase storage for PII and sensitive data.')
parser.add_argument('--connection', action='store', help='YAML Connection file path')
parser.add_argument('--fingerprint', action='store', help='Override YAML fingerprint file path')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')
parser.add_argument('--shutup', action='store_true', help='Suppress the Hawk Eye banner 🫣', default=False)

args, extra_args = parser.parse_known_args()

def get_connection():
    if args.connection:
        if os.path.exists(args.connection):
            with open(args.connection, 'r') as file:
                connections = yaml.safe_load(file)
                return connections
        else:
            print_error(f"Connection file not found: {args.connection}")
            exit(1)
    else:
        print_error(f"Please provide a connection file using --connection flag")
        exit(1)

def get_fingerprint_file():
    if args.fingerprint:
        if os.path.exists(args.fingerprint):
            with open(args.fingerprint, 'r') as file:
                return yaml.safe_load(file)
        else:
            print_error(f"Fingerprint file not found: {args.fingerprint}")
            exit(1)
    else:
        if os.path.exists('fingerprint.yml'):
            with open('fingerprint.yml', 'r') as file:
                return yaml.safe_load(file)
        else:
            print_error(f"Default Fingerprint file not found: fingerprint.yml")
            exit(1)
    
def print_info(message):
    console.print(f"[yellow][INFO][/yellow] {message}")

def print_debug(message):
    if args.debug:
        console.print(f"[blue][DEBUG][/blue] {message}")

def print_error(message):
    console.print(f"[bold red]❌ {message}")

def print_success(message):
    console.print(f"[bold green]✅ {message}")

def print_info(message):
    console.print(f"[yellow][INFO][/yellow] {message}")
def print_alert(message):
    console.print(f"[bold red][ALERT][/bold red] {message}")

def print_banner():
    banner = r"""
                                /T /I
                                / |/ | .-~/
                            T\ Y  I  |/  /  _
            /T               | \I  |  I  Y.-~/
            I l   /I       T\ |  |  l  |  T  /
        T\ |  \ Y l  /T   | \I  l   \ `  l Y
    __  | \l   \l  \I l __l  l   \   `  _. |
    \ ~-l  `\   `\  \  \\ ~\  \   `. .-~   |
    \   ~-. "-.  `  \  ^._ ^. "-.  /  \   |
    .--~-._  ~-  `  _  ~-_.-"-." ._ /._ ." ./
    >--.  ~-.   ._  ~>-"    "\\   7   7   ]
    ^.___~"--._    ~-{  .-~ .  `\ Y . /    |
    <__ ~"-.  ~       /_/   \   \I  Y   : |
    ^-.__           ~(_/   \   >._:   | l______
        ^--.,___.-~"  /_/   !  `-.~"--l_ /     ~"-.                 + ================================================== +
                (_/ .  ~(   /'     "~"--,Y   -=b-. _)               + [bold yellow]H[/bold yellow].[bold yellow]A[/bold yellow].[bold yellow]W[/bold yellow].[bold yellow]K[/bold yellow] [bold yellow]Eye[/bold yellow] - [bold blue]Highly Advanced Watchful Keeper Eye[/bold blue] +
                (_/ .  \  :           / l      c"~o \               + ================================================== +
                    \ /    `.    .     .^   \_.-~"~--.  )                 
                    (_/ .   `  /     /       !       )/                   Hunt for Secrets & PII Data, like never before!
                    / / _.   '.   .':      /        '                           A Tool by [bold red]Rohit Kumar (@rohitcoder)[/bold red]
                    ~(_/ .   /    _  `  .-<_                                    
                        /_/ . ' .-~" `.  / \  \          ,z=.
                        ~( /   '  :   | K   "-.~-.______//
                        "-,.    l   I/ \_______{--->._(=====.
                        //(     \  <                  \\
                        /' /\     \  \                 \\
                        .^. / /\     "  }__ //===--`\\
                    / / ' '  "-.,__ {---(==-
                    .^ '       :  T  ~"   ll       
                    / .  .  . : | :!        \\
                (_/  /   | | j-"             ~^~^
                    ~-<_(_.^-~"
    """
    if not args.shutup:
        console.print(banner)

def match_strings(content):
    matched_strings = []
    patterns = get_fingerprint_file()
    for pattern_name, pattern_regex in patterns.items():
        print_debug(f"Matching pattern: {pattern_name}")
        found = {} 
        ## parse pattern_regex as Regex
        complied_regex = re.compile(pattern_regex, re.IGNORECASE)
        matches = re.findall(complied_regex, content)
        if matches:
            found['pattern_name'] = pattern_name
            found['matches'] = matches
            found['sample_text'] = content[:50]
            matched_strings.append(found)
    return matched_strings

def should_exclude_file(file_name, exclude_patterns):
    _, extension = os.path.splitext(file_name)
    if extension in exclude_patterns:
        print_debug(f"Excluding file: {file_name} because of extension: {extension}")
        return True
    
    for pattern in exclude_patterns:
        if pattern in file_name:
            print_debug(f"Excluding file: {file_name} because of pattern: {pattern}")
            return True
    return False

def should_exclude_folder(folder_name, exclude_patterns):
    for pattern in exclude_patterns:
        if pattern in folder_name:
            return True
    return False

def list_all_files_iteratively(path, exclude_patterns):
    for root, dirs, files in os.walk(path, topdown=True):
        dirs[:] = [d for d in dirs if not should_exclude_folder(os.path.join(root, d), exclude_patterns)]

        for file in files:
            if not should_exclude_file(file, exclude_patterns):
                yield os.path.join(root, file)

def read_match_strings(file_path, source):
    print_info(f"Scanning file: {file_path}")
    content = ''
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except Exception as e:
        pass
    matched_strings = match_strings(content)
    return matched_strings

def SlackNotify(msg):
    connections = get_connection()

    if 'notify' in connections:
        slack_config = connections['notify'].get('slack', {})
        webhook_url = slack_config.get('webhook_url', '')
        if webhook_url != '':
            try:
                payload = {
                    'text': msg,
                }
                headers = {'Content-Type': 'application/json'}
                requests.post(webhook_url, data=json.dumps(payload), headers=headers)
            except Exception as e:
                print_error(f"An error occurred: {str(e)}")
