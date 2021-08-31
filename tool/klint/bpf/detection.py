import platform

_override_linux_version = None
_override_64bit = None

def get_linux_version():
    global _override_linux_version
    if _override_linux_version is not None:
        return _override_linux_version
    if platform.system() != 'Linux':
        return None
    return platform.release()

def is_64bit():
    global _override_64bit
    if _override_64bit is not None:
        return _override_64bit
    # https://stackoverflow.com/a/12578715
    return platform.machine().endswith('64')

def override_linux_version(value):
    global _override_linux_version
    _override_linux_version = value

def override_64bit(value):
    global _override_64bit
    _override_64bit = value