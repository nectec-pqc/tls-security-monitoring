#! /bin/bash

if [ -f openssl-ciphers.pod.in ]; then
  echo 'openssl-ciphers.pod.in already exists. Delete it first if you want to re-download it from source.'
else
  wget https://raw.githubusercontent.com/openssl/openssl/refs/heads/master/doc/man1/openssl-ciphers.pod.in
fi

sed '/^=head1 CIPHER SUITE NAMES/,/^=head1/!d' openssl-ciphers.pod.in |
  sed '/^ /!d' |
  sed '/alias of/d' |
  sed -E 's/ (\w*)\s+/\1,/' \
  > cipher-names.csv
