#!/usr/bin/env python

import crypt

def sha512_shadow_string(passwd, salt):
    full_salt = '$6${}'.format(salt)
    return crypt.crypt(passwd, full_salt)

salt = 'XRpB311l'
passwd = 'testpass'
sha = sha512_shadow_string(passwd, salt)
print(sha)
