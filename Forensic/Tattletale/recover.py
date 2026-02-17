import struct

# Standard Linux Input Event Codes
# We need letters, numbers, and specific symbols used in the command
KEY_MAP = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    12: '-', 14: '[BACKSPACE]', 16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 
    21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 30: 'a', 31: 's', 32: 'd', 33: 'f', 
    34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 44: 'z', 45: 'x', 46: 'c', 
    47: 'v', 48: 'b', 49: 'n', 50: 'm', 57: ' '
}

def recover_password():
    data_struct = 'QQHHi' # struct input_event: time(16), type(2), code(2), value(4)
    chunk_size = struct.calcsize(data_struct)
    
    chars = []
    caps_on = False
    shift_on = False
    
    with open('dist/cron.aseng', 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            
            _, _, type_, code, value = struct.unpack(data_struct, chunk)
            
            if type_ == 1: # EV_KEY
                # Handle Modifier Keys
                if code == 58 and value == 1: caps_on = not caps_on # CapsLock Toggle
                if code in [42, 54]: shift_on = (value == 1)        # Shift Hold
                
                if value == 1 and code in KEY_MAP:
                    key = KEY_MAP[code]
                    
                    if key == '[BACKSPACE]':
                        if chars: chars.pop()
                    else:
                        # Handle Shift/Caps logic
                        if key == '-' and shift_on: key = '_'
                        elif key == ';' and shift_on: key = ':'
                        elif key.isalpha():
                            if shift_on ^ caps_on: key = key.upper()
                            
                        chars.append(key)

    # Reconstruct log and grab the password argument
    full_log = "".join(chars)
    # Looks for "... -pass pass:PASSWORD ..."
    return full_log.split("pass:")[-1].split(" ")[0]

if __name__ == "__main__":
    print(f"Recovered Password: {recover_password()}")
