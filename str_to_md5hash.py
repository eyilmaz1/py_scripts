import hashlib
import sys

def computeMD5hash(my_string):
    m = hashlib.md5()
    m.update(my_string.encode('utf-8'))
    return m.hexdigest()

print(computeMD5hash(sys.argv[1]))
