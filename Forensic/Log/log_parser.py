import re

log_file = 'access.log'
# Regex captures the character position and its ASCII value
email_pattern = re.compile(r'user_email.*?%2C(\d+)%2C1%29%29%21%3D(\d+)')
pass_pattern  = re.compile(r'user_pass.*?%2C(\d+)%2C1%29%29%21%3D(\d+)')

def parse_log(pattern):
    recovered = {}
    with open(log_file, 'r', errors='ignore') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                pos, val = map(int, match.groups())
                recovered[pos] = chr(val)
    return "".join(recovered[i] for i in sorted(recovered))

print(f"Email: {parse_log(email_pattern)}")
print(f"Hash:  {parse_log(pass_pattern)}")