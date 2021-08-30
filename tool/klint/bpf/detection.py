import platform

def get_linux_version():
    if platform.system() != 'Linux':
        return None
    return platform.release()

def is_64bit():
    # https://stackoverflow.com/a/12578715
    return platform.machine().endswith('64')
