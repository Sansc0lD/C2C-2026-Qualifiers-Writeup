import numpy
import string
from functools import wraps
from collections import Counter
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
env.globals["numpy"] = numpy

def waf(content):
    allowlist = set(string.ascii_lowercase + string.ascii_uppercase + string.punctuation + string.digits + ' ')
    blocklist = ['fromfile', 'savetxt', 'load', 'array', 'packbits', 'ctypes', 'eval', 'exec', 'breakpoint', 'input', '+', '-', '/', '\\', '|', '"', "'"]
    char_limits = {
        '(': 3,
        ')': 3,
        '[': 3,
        ']': 3,
        '{': 3,
        '}': 3,
        ',': 10
    }

    if len(content) > 275:
        raise ValueError("Nope")

    for ch in content:
        if ch not in allowlist:
            raise ValueError("Nope")

    lower_value = content.lower()
    for blocked in blocklist:
        if blocked.lower() in lower_value:
            raise ValueError("Nope")

    counter = Counter(ch for ch in content if ch in char_limits)
    for ch, count in counter.items():
        if count > char_limits[ch]:
            raise ValueError("Nope")

def main():
    content = input(">>> ")

    try:
        waf(content)
        result = env.from_string(content).render()
        print(result)
    except ValueError as e:
        print(e.args[0])
    except Exception:
        print("Nope")

if __name__ == "__main__":
    main()
