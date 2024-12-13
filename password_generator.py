import random

char_set = list(enumerate([
    'abcdefghijklmnopqrstuvwxyz', # Lowercase
    '0123456789', # Numbers
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ', # Uppercase
    '!-_.' # Special characters
]))

def generate_pass(length=21):
    """Function to generate a password"""

    password = []
    prev = -1

    while len(password) < length:
        i, a_char_set = random.choice(char_set)
        if i == prev:
            continue
        else:
            prev = i
            a_char = random.choice(a_char_set)
            password.append(a_char)

    return ''.join(password)

if __name__ == '__main__':
    print (generate_pass())
