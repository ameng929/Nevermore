__author__ = 'qmwang'
import sys
try:

    passwd = sys.argv[1]
except:
    print "Usage: %s <Password>" % sys.argv[0]
    sys.exit(0)
ascii = list
char =list
for i in range(0, len(passwd)):
    if passwd[i] == '9':
        #char[i][0] = '9'
        print '9'
        continue

    re = ord(passwd[i]) - ord('!')
    if re >= 47 and re < 51:
        #char[i][0] = chr(re)
        print chr(re)
    re = ord(passwd[i]) - ord('/')
    if re >= 51 and re < 55:
        #char[i][1] = chr(re)
        print chr(re)
    re = ord(passwd[i]) - ord('B')
    if re >= 55 and re < 57:
        #char[i][2] = chr(re)
        print chr(re)
print char