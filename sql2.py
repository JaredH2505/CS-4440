from pymd5 import md5
import random
import string
import re
validChoices = string.ascii_lowercase + string.ascii_uppercase
#str(hash.digest(),'utf-8')
while True:
    try:
        input = ''.join(random.choice(validChoices) for i in range(0,32))
        hash = md5()
        hash.update(input)
        #out = str(hash.digest(),'utf-8')
        #print(out)
        if re.search(b"'-'",hash.digest()):
            print("valid string")
            print(input)
            #print(out)
            break;
    except UnicodeDecodeError:
        pass