import ipaddress
import socket
import sys

from colorama import Fore, Style


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def resolve_domain_to_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def print_header(text: str) -> None:
    print(f"\n{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print(Style.BRIGHT + "_" * len(text) + Style.RESET_ALL)


def print_ok(text: str) -> None:
    print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")


def print_warn(text: str) -> None:
    print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")


def print_bad(text: str) -> None:
    print(f"{Fore.RED}{text}{Style.RESET_ALL}")


def print_info(text: str) -> None:
    print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")


def print_wait(remaining_seconds: int, message: str) -> None:
    """Aynı satırı güncelleyerek geri sayım gösterir. remaining_seconds 0
    olduğunda satırı temizler (geri sayımın bittiğini belirtmek için)."""
    if remaining_seconds <= 0:
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()
        return

    text = f"{message} {remaining_seconds} sn..."
    sys.stdout.write(f"\r{Fore.CYAN}{text}{Style.RESET_ALL}" + " " * 10)
    sys.stdout.flush()
