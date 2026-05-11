import os
from colorama import Fore, Style, init

init(autoreset=True, strip=True)
ENABLE_COLORS = os.getenv("CLI_MODE", "1") == "1"

def info(msg):
    print(Fore.CYAN + msg if ENABLE_COLORS else msg)

def success(msg):
    print(Fore.GREEN + msg if ENABLE_COLORS else msg)

def warning(msg):
    print(Fore.YELLOW + msg if ENABLE_COLORS else msg)

def error(msg):
    print(Fore.RED + msg if ENABLE_COLORS else msg)

def highlight(msg):
    print(Fore.MAGENTA + msg if ENABLE_COLORS else msg)