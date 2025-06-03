import argparse
import config
import re
import requests
import sys
from ipaddress import ip_address, ip_network

__VERSION__ = "1.0.0"
__AUTHOR__ = "TheresNoTime"
blocked_nets_re = re.compile(r"blocked_nets.*?acme", re.DOTALL | re.IGNORECASE)
cidrs_re = re.compile(
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}", re.DOTALL | re.IGNORECASE
)


def is_ip(ip: str) -> bool:
    """Check if the given string is a valid IP address."""
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def fetch_hiera_data(url: str) -> list[str]:
    """Fetch Hiera data from the given URL and return a list of blocked CIDRs."""
    headers = {"User-Agent": f"ip-in-ranges/{__VERSION__} ({__AUTHOR__})"}
    if not url.startswith("http"):
        raise ValueError("HIERA_URL must start with http:// or https://")
    response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
    if response.status_code != 200:
        raise Exception(
            f"Failed to fetch data from {url}, status code: {response.status_code}"
        )
    response.encoding = "utf-8"
    blocked_nets = blocked_nets_re.search(response.text)
    if blocked_nets:
        cidr_list = blocked_nets.group(0)
        cidrs = cidrs_re.findall(cidr_list)
        if cidrs:
            return cidrs
    return []


def find_cidr(ip: str, cidrs: list[str]) -> str | bool:
    """Check if the given IP address is in any of the provided CIDRs."""
    ip_obj = ip_address(ip)
    for cidr in cidrs:
        if ip_obj in ip_network(cidr):
            return cidr
    return False


def check_config():
    """Check if the required configuration is set."""
    if not hasattr(config, "HIERA_URL") or not config.HIERA_URL:
        raise ValueError("HIERA_URL is not set in config.py")


if __name__ == "__main__":
    check_config()

    parser = argparse.ArgumentParser(
        description="Check if an IP address is in blocked CIDRs from Hiera data.",
    )
    parser.add_argument(
        "-a",
        "--ip",
        action="store",
        type=str,
        metavar="1.1.1.1",
        help="IP address to check",
        required=True,
    )
    parser.add_argument(
        "--use-list",
        action="store",
        metavar="cidrs.txt",
        help="Use a list of blocked CIDRs instead of fetching (1 CIDR per line)",
        default=None,
        type=str,
        required=False,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__VERSION__} by {__AUTHOR__}"
    )
    args = parser.parse_args()

    ip = args.ip.strip()
    if not is_ip(ip):
        print(f"{ip} is not a valid IP address.")
        sys.exit()

    print(f"Checking if {ip} is in blocked CIDRs...")
    if not args.use_list:
        print("Fetching blocked CIDRs from Hiera data...")
        try:
            cidrs = fetch_hiera_data(config.HIERA_URL)
        except Exception as e:
            print(f"Error fetching Hiera data: {e}")
            sys.exit()
    else:
        print(f"Using list of blocked CIDRs from {args.use_list}...")
        try:
            with open(args.use_list, "r") as file:
                cidrs = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"File {args.use_list} not found.")
            sys.exit()
        except Exception as e:
            print(f"Error reading file {args.use_list}: {e}")
            sys.exit()

    if not cidrs:
        print("No CIDRs found in the Hiera data.")
        sys.exit()
    else:
        print(f"Found {len(cidrs)} blocked CIDRs.")
        # ip = "38.242.188.189"
        result = find_cidr(ip, cidrs)
        if not result:
            print(f"{ip} is not in any blocked CIDR")
        else:
            print(f"{ip} is in blocked CIDR {result}")
