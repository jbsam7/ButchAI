import os

# Generate the random salt
salt = os.urandom(16).hex()
print(salt)
