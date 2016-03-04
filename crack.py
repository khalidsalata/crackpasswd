
from misc import *
import crypt
import re

def load_words(filename,regexp):
    """Load the words from the file filename that match the regular
       expression regexp.  Returns a list of matching words in the order
       they are in the file."""
    l = []
    f = open(filename, 'r')
    for line in f:
        if re.search(regexp,line) is not None : l.append(line.rstrip('\n'))
    return l

def transform_reverse(str):
    m = str[::-1]
    l = [str,m]
    return l

def transform_capitalize(str):
    q = []
    q.append(str)
    p = str.lower()
    for c in range(0,len(p)):
        w = p
        for f in range(0,len(p)):
            l = p[:f]
            r = p[(f+1):]
            x = p[f].swapcase()
            if (l+x+r) not in q : q.append(l+x+r)
        p = w
        lp = p[:c]
        rp = p[(c+1):]
        xp = p[c].swapcase()
        p = lp+xp+rp
        for f in range(0,len(p)):
            l = p[:f]
            r = p[(f+1):]
            x = p[f].swapcase()
            if (l+x+r) not in q : q.append(l+x+r)
    return q

def transform_digits(str):
    d = { "o" : ["0"], "i" : ["1"], "l" : ["1"], "z" : ["2"], "e" : ["3"], "a" : ["4"], "s" : ["5"], "b" : ["6","8"], "t" : ["7"], "g" : ["9"], "q" : ["9"]}
    q = []
    p = str
    for c in range(0,len(p)):
        for f in range(0,len(p)):
            l = p[:f]
            r = p[(f+1):]
            a = p[f].lower()
            if a in d :
                for s in d[a]:
                    if l+s+r not in q : q.append(l+s+r)
            elif (l+p[f]+r) not in q : q.append(l+p[f]+r)
        lc = p[:c]
        rc = p[(c+1):]
        ac = p[c].lower()
        if ac in d : xc = d[ac][0]
        else : xc = p[c]
        m = (lc+xc+rc)
        for f in range(0,len(p)):
            l = m[:f]
            r = m[(f+1):]
            a = m[f].lower()
            if a in d :
                for s in d[a]:
                    if l+s+r not in q : q.append(l+s+r)
            elif (l+p[f]+r) not in q : q.append(l+p[f]+r)

    #q.append(str)
    return q

def check_pass(plain,enc):
    """Check to see if the plaintext plain encrypts to the encrypted
       text enc"""
    pre = enc[:2]
    check = crypt.crypt(plain,pre)
    if check == enc : return True
    else : return False

def load_passwd(filename):
    """Load the password file filename and returns a list of
       dictionaries with fields "account", "password", "UID", "GID",
       "GECOS", "directory", and "shell", each mapping to the
       corresponding field of the file."""
    l = []
    f = open(filename,'r')
    for line in f:
        d = {}
        linel = line.split(":")
        d['account'] = linel[0]
        d['password'] = linel[1]
        d['UID'] = int(linel[2])
        d['GID'] = int(linel[3])
        d['GECOS'] = linel[4]
        d['directory'] = linel[5]
        d['shell'] = linel[6].rstrip('\n')
        l.append(d)
    return l

def crack_pass_file(pass_filename,words_filename,out_filename):
    """Crack as many passwords in file fn_pass as possible using words
       in the file words"""
    fo = open(out_filename, 'w', 0)
    pass_d = load_passwd(pass_filename)
    passes = []
    for m in pass_d:
        passes.append((m['account'],m['password']))

    w = load_words(words_filename, r"^.{6,8}$")

    ans = []
    for i in w:
        for p in passes:
            if check_pass(i,p[1]) is True:
                fo.write(p[0]+"="+i+'\n')
                ans.append((p[0],i))
                passes.remove(p)
                w.remove(i)

    candidates = []
    for i in w:
        permutations = []
        pl = transform_digits(i)
        for r in pl:
            rl = transform_capitalize(r)
            for x in rl:
                xl = transform_reverse(x)
                for w in xl:
                    permutations.append(w)
        candidates.append(permutations)

    for c in candidates:
        for p in passes:
            for x in c:
                if check_pass(x,p[1]) is True:
                    fo.write(p[0]+"="+i+'\n')
                    ans.append((p[0],c))
                    candidates.remove(c)
                    passes.remove(p)

