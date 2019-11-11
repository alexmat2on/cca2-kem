import random
import string

s = ""
for i in range(0, 4):
    s += random.choice(string.ascii_letters)

print(s)
