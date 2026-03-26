from colorama import Fore, Style, init

init(autoreset=True)

def info(msg):
    print(Fore.CYAN + msg)

def success(msg):
    print(Fore.GREEN + msg)

def warning(msg):
    print(Fore.YELLOW + msg)

def error(msg):
    print(Fore.RED + msg)

def highlight(msg):
    print(Fore.MAGENTA + msg)
