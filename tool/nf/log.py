class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_informatively(result, hope, message):
    """
    Given the obtained result vs what was hoped for,
    the function prints the message in right color!
    :param result: bool
    :param hope: bool
    :param message: string
    """
    if result == hope:
        print(f"{bcolors.OKGREEN}{message}{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}{message}{bcolors.ENDC}")

def print_red(message):
    print(f"{bcolors.FAIL}{message}{bcolors.ENDC}")

def print_green(message):
    print(f"{bcolors.OKGREEN}{message}{bcolors.ENDC}")