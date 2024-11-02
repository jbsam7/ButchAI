import random

lower_char = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i','z', 'w', 'p', 'n', 'm', 'u', 'A', 'Y', 'y', 'R', 'W', 'E', 'V', 'N', 'B', 'Q']
weird_char = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '?', '.']


user_input = int(input('Please enter how many characters needed for your REMOVED: '))

length = user_input

empty = []
for i in range(length):
    char = random.choice(weird_char)
    random_char = random.choice(lower_char)
    if i % 2 == 0:
        empty.append(char)
    else:
        empty.append(random_char)
    

print(empty)
empty = ''.join(empty)
print(empty)
