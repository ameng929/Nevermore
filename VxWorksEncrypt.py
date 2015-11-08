import sys

try:
    text = sys.argv[1]
except:
    print "Usage: %s <text>" % sys.argv[0]
    sys.exit(0)

#text = 'M9BH%57)'
text = '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
#text = '!!!!!!!!'
magic = 31695317

#if len(text)<8 or len(text) >40:
if len(text) > 40:
    print 'Input invalid text'
    sys.exit(0)
passwdint = 0
for i in range(0, len(text)):
    passwdint += (ord(text[i]) * (i+1) ^ (i+1))
    print passwdint

print passwdint * magic
#out = str(passwdint * magic & 0xffffffff)
out = '%u' % (passwdint * magic & 0xffffffff)
print out
encrypt = list(out)
print encrypt

encrypt = list('1234567890')

for i in range(0, len(encrypt)):
    if encrypt[i] < '3':
        encrypt[i] = chr(ord(encrypt[i])+ord('!'))
    if encrypt[i] < '7':
        encrypt[i] = chr(ord(encrypt[i])+ord('/'))
    if encrypt[i] < '9':
        encrypt[i] = chr(ord(encrypt[i])+ord('B'))
print encrypt

