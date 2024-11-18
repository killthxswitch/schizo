import asyncio
import sys
import subprocess
from pathlib import Path
from colorama import Fore, Style, init
from scanners.repository_scanner import RepositoryScannerAsync
from utils.reporting import generate_report_to_json

# Initialize colorama for cross-platform support
init(autoreset=True)

def display_banner():
    """Display an ASCII banner for the tool."""
    banner = r"""
   ____  _       _     _                
  / ___|| | ___ | |_  | |__   __ _ _ __ 
  \___ \| |/ _ \| __| | '_ \ / _` | '__|
   ___) | | (_) | |_  | | | | (_| | |   
  |____/|_|\___/ \__| |_| |_|\__,_|_|   
                                        
"""
    print(f"{Fore.MAGENTA}{banner}")

def load_urls_from_file(file_path):
    """Read URLs from a file, one per line."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: File '{file_path}' not found.")
        return []

def generate_target_list(output_file, ip_range, rate):
    """
    Use Masscan to scan for open ports and generate a target list file.

    Args:
        output_file (str): Path to save the generated target list.
        ip_range (str): CIDR notation of IP range to scan (e.g., "192.168.1.0/24").
        rate (int): Packets per second for Masscan.

    Returns:
        None
    """
    masscan_path = "./tools/masscan"  # Path to the embedded Masscan binary
    print(f"{Fore.YELLOW}[+] Running embedded Masscan... This may take a while.")
    masscan_cmd = [
        masscan_path,
        "-p80,443,9418",  # Ports to scan
        "--rate", str(rate),  # Rate of packets per second
        ip_range,  # IP range to scan
        "-oL", "masscan_output.txt"  # Save output in Masscan's list format
    ]

    try:
        subprocess.run(masscan_cmd, check=True)
        print(f"{Fore.GREEN}[+] Masscan completed. Parsing results...")

        # Parse Masscan output to extract IPs
        ips = set()
        with open("masscan_output.txt", "r") as f:
            for line in f:
                if line.startswith("#"):  # Skip comments
                    continue
                parts = line.split()
                if len(parts) > 3 and parts[1] == "open":
                    ips.add(parts[3])  # IP address is the 4th field

        # Save IPs to the target list file
        Path(output_file).write_text("\n".join(ips))
        print(f"{Fore.BLUE}[+] Target list saved to {output_file}")

    except FileNotFoundError:
        print(f"{Fore.RED}[!] Embedded Masscan not found at {masscan_path}.")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] Masscan failed: {str(e)}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}")

async def scan_url(url):
    print(f"\n{Fore.YELLOW}Scanning {url}...")
    scanner = RepositoryScannerAsync(url)
    results = await scanner.scan_sensitive_files()
    return {url: results}

async def scan_from_list():
    """Scan URLs entered manually."""
    urls = []
    print(f"{Fore.CYAN}[+] Enter URLs one by one (type 'done' to finish):")
    while True:
        url = input(f"{Fore.GREEN}Enter URL: ").strip()
        if url.lower() == "done":
            break
        urls.append(url)

    if not urls:
        print(f"{Fore.RED}[!] No URLs entered. Returning to menu.")
        return

    tasks = [scan_url(url) for url in urls]
    all_results = {}
    for result in await asyncio.gather(*tasks):
        all_results.update(result)

    generate_report_to_json(all_results, output_file="scan_report.json")
    print(f"{Fore.BLUE}[+] Results saved to scan_report.json")

async def scan_from_file():
    """Scan URLs from a file."""
    file_path = input(f"{Fore.GREEN}Enter the path to the file with URLs: ").strip()
    urls = load_urls_from_file(file_path)

    if not urls:
        print(f"{Fore.RED}[!] No URLs found in the provided file. Returning to menu.")
        return

    tasks = [scan_url(url) for url in urls]
    all_results = {}
    for result in await asyncio.gather(*tasks):
        all_results.update(result)

    generate_report_to_json(all_results, output_file="scan_report.json")
    print(f"{Fore.BLUE}[+] Results saved to scan_report.json")

async def generate_with_masscan():
    """Generate a target list using Masscan."""
    ip_range = input(f"{Fore.GREEN}Enter the IP range to scan (e.g., 192.168.1.0/24): ").strip()
    rate = input(f"{Fore.GREEN}Enter the scan rate (packets per second, e.g., 1000): ").strip()

    try:
        rate = int(rate)
    except ValueError:
        print(f"{Fore.RED}[!] Invalid rate. Please enter a valid number.")
        return

    output_file = input(f"{Fore.GREEN}Enter the output file for the target list: ").strip()
    generate_target_list(output_file, ip_range, rate)

def show_menu():
    """Display the interactive menu."""
    print(f"\n{Fore.MAGENTA}=== Sensitive File Scanner ===")
    print(f"{Fore.CYAN}1. Scan URLs manually (enter URLs)")
    print(f"{Fore.CYAN}2. Scan URLs from a file")
    print(f"{Fore.CYAN}3. Generate target list with Masscan")
    print(f"{Fore.RED}4. Exit")
    print(f"{Fore.MAGENTA}==============================")

async def main():
    display_banner()
    while True:
        show_menu()
        choice = input(f"{Fore.GREEN}Select an option: ").strip()
        if choice == "1":
            await scan_from_list()
        elif choice == "2":
            await scan_from_file()
        elif choice == "3":
            await generate_with_masscan()
        elif choice == "4":
            print(f"{Fore.YELLOW}[+] Exiting. Goodbye!")
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    asyncio.run(main())
