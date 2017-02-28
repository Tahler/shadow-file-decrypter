#!/usr/bin/env python

import itertools as it
import crypt

def encrypt(hash_algo_num, salt, passwd):
    """Returns the password hash (not the entire shadow line string)."""
    full_salt = '${}${}'.format(hash_algo_num, salt)
    full_shadow = crypt.crypt(passwd, full_salt)
    start_of_password_hash = len(full_salt) + 1
    passwd_hash = full_shadow[start_of_password_hash:]
    return passwd_hash


def possible_passwds(length, possible_chars):
    """Generator for all possible combinations of possible_chars of a length"""
    # TODO: could optimize - increase length by adding each possible char to
    # each combination. no recalculation
    return [''.join(cmb) for cmb in it.product(possible_chars, repeat=length)]


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

    def crack(self, min_pass_len, max_pass_len, possible_chars):
        """Attacks the hash with all possible combinations, increasing in length

        Returns: The password if a matching password was found; None otherwise
        """
        for length in range(min_pass_len, max_pass_len + 1):
            for possible_passwd in possible_passwds(length, possible_chars):
                print(possible_passwd, end='\r')
                # Resembles $6$salt$hashed-passwd
                shadow_hash = encrypt(
                        self._hash_algo_num,
                        self._salt,
                        possible_passwd)
                if shadow_hash == self._passwd_hash:
                    return possible_passwd
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
    """Parses a line from the /etc/shadow file into a ShadowLine."""

    line_pieces = line.split(':')
    username = line_pieces[0]
    passwd = line_pieces[1]
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

MIN_PASSWD_LEN = 3
MAX_PASSWD_LEN = 3
POSSIBLE_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

passwd_hash = '$6$vb1tLY1qiY$jBQv/SXasS2vPiVJRsyY3udTsmeSHPiv23UjqB47UaLChPJ.wcABC.XQxyLNwAT7UgQsGXvQRt.We5gpbDXp20'
line = 'tberry:{}:17148:0:99999:7:::'.format(passwd_hash)
shadow_line = parse_shadow_line(line)
sha = shadow_line.crack(MIN_PASSWD_LEN, MAX_PASSWD_LEN, POSSIBLE_CHARS)
print(sha)
