#!/usr/bin/env python

import crypt
import os
import itertools as it
import string

from multiprocessing import Pool as ThreadPool

MIN_PASSWD_LEN = 3
MAX_PASSWD_LEN = 5
POSSIBLE_CHARS = string.ascii_lowercase + string.ascii_uppercase + string.digits

CHECKPOINT_FILE = 'checkpoint'
CHECKPOINT_NUM = 10000

def first(iterable):
    """Like `any`, but returns the first truthy value in `iterable`. Returns
    `None` if `any` would return false."""
    return next((item for item in iterable if item), None)


def consume(iterator, n):
    """Advance the iterator n-steps ahead. If n is none, consume entirely."""
    # Use functions that consume iterators at C speed.
    if n is None:
        # feed the entire iterator into a zero-length deque
        collections.deque(iterator, maxlen=0)
    else:
        # advance to the empty slice starting at position n
        next(it.islice(iterator, n, n), None)


def encrypt(hash_algo_num, salt, passwd):
    """Returns the password hash (not the entire shadow line string)."""
    full_salt = '${}${}'.format(hash_algo_num, salt)
    full_shadow = crypt.crypt(passwd, full_salt)
    start_of_password_hash = len(full_salt) + 1
    passwd_hash = full_shadow[start_of_password_hash:]
    return passwd_hash


def _possible_passwds(min_length, max_length, possible_chars):
    """Generates all possible combinations of `possible_chars` between
    `min_length` and `max_length` (inclusive) characters long."""
    for i in range(min_length, max_length + 1):
        for cmb in it.product(possible_chars, repeat=i):
            cmb_str = ''.join(cmb)
            yield cmb_str


def possible_passwds(min_length, max_length, possible_chars):
    last_chkpt = load_checkpoint()
    print('starting from:', last_chkpt)
    iterator = iter(_possible_passwds(min_length, max_length, possible_chars))
    consume(iterator, last_chkpt)
    acc = 0
    for passwd in iterator:
        if acc == CHECKPOINT_NUM:
            acc = 0
            write_checkpoint()
        else:
            acc += 1
        yield passwd


def write_checkpoint():
    """Increments the `CHECKPOINT_FILE` by `CHECKPOINT_NUM`"""
    last_chkpt = load_checkpoint()
    with open(CHECKPOINT_FILE, 'w') as f:
        new_chkpt = last_chkpt + CHECKPOINT_NUM
        f.write(str(new_chkpt))


def load_checkpoint():
    """Creates or reads a number from the `CHECKPOINT_FILE`"""
    try:
        f = open(CHECKPOINT_FILE, 'r')
        line = f.readline()
        return int(line) if line else 0
    except FileNotFoundError:
        with open(CHECKPOINT_FILE, 'w') as f:
            f.write(str(0))
            f.flush()
            return 0
    finally:
        f.close()


class ShadowLine(object):
    """Represents a line from an /etc/shadow file"""

    def __init__(self, username, hash_algo_num, salt, passwd_hash,
                 last_passwd_change, min_days_between_passwd_changes,
                 passwd_validity, warning_threshold, account_inactive,
                 num_days_since_disable):
        """Inits a ShadowLine. All args are strings."""
        self._username = username
        self._hash_algo_num = hash_algo_num
        self._salt = salt
        self._passwd_hash = passwd_hash
        self._last_passwd_change = last_passwd_change
        self._min_days_between_passwd_changes = min_days_between_passwd_changes
        self._passwd_validity = passwd_validity
        self._warning_threshold = warning_threshold
        self._account_inactive = account_inactive
        self._num_days_since_disable = num_days_since_disable

    def _is_correct_passwd(self, passwd):
        """Returns `True` if `passwd` is correct; `False` otherwise"""
        print('{}:'.format(self._username), passwd, end='\r')
        passwd_hash = encrypt(self._hash_algo_num, self._salt, passwd)
        return passwd_hash == self._passwd_hash

    def _test_passwd(self, passwd):
        """Returns `passwd` if `passwd` is correct; None otherwise"""
        return passwd if self._is_correct_passwd(passwd) else None

    def crack(self,
              min_pass_len=MIN_PASSWD_LEN,
              max_pass_len=MAX_PASSWD_LEN,
              possible_chars=POSSIBLE_CHARS):
        """Attacks the hash with all possible combinations, increasing in length

        Returns: The password if a matching password was found; None otherwise
        """
        with ThreadPool() as p:
            passwd = first(
                    p.imap_unordered(
                        self._test_passwd,
                        possible_passwds(
                            min_pass_len,
                            max_pass_len,
                            possible_chars)))
            if passwd is not None:
                return passwd
        return None

    def get_passwd_field(self):
        return '${}${}${}'.format(
                self._hash_algo_num,
                self._salt,
                self._passwd_hash)

    def get_line(self):
        """Returns the line as it would appear in the /etc/shadow file."""
        return '{}:{}:{}:{}:{}:{}:{}:{}'.format(
                self._username,
                self.get_passwd_field(),
                self._last_passwd_change,
                self._min_days_between_passwd_changes,
                self._passwd_validity,
                self._warning_threshold,
                self._account_inactive,
                self._num_days_since_disable)


def parse_shadow_line(line):
    """Parses a line from the /etc/shadow file into a ShadowLine.

    Returns None if the line does not have an encrypted password.
    """

    line_pieces = line.split(':')
    username = line_pieces[0]
    passwd = line_pieces[1]
    if not passwd.startswith('$'):
        return None

    last_passwd_change = line_pieces[2]
    min_days_between_passwd_changes = line_pieces[3]
    passwd_validity = line_pieces[4]
    warning_threshold = line_pieces[5]
    account_inactive = line_pieces[6]
    num_days_since_disable = line_pieces[7]

    # Skip the first '$'
    passwd_pieces = passwd[1:].split('$')
    hash_algo_num = passwd_pieces[0]
    salt = passwd_pieces[1]
    passwd_hash = passwd_pieces[2]

    return ShadowLine(
            username,
            hash_algo_num,
            salt,
            passwd_hash,
            last_passwd_change,
            min_days_between_passwd_changes,
            passwd_validity,
            warning_threshold,
            account_inactive,
            num_days_since_disable)


def crack_shadow_file(filename):
    with open(filename) as f:
        for line in f:
            shadow_line = parse_shadow_line(line)
            if shadow_line is not None:
                passwd = shadow_line.crack()
                user = shadow_line._username
                print('{}:'.format(user), passwd)

def main():
    # TODO: fancy CLI parsing
    filename = os.sys.argv[1]
    crack_shadow_file(filename)
    os.remove(CHECKPOINT_FILE)

if __name__ == '__main__':
    main()
