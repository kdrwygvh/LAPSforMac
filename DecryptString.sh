#!/bin/bash

DecryptString="${1}"
DECRYPTED=$(echo "${DecryptString}" | openssl enc -aes256 -d -a -A -S "5257f8db1bb5827d" -k "05d599f313aaf0338e048fe7")
echo $DECRYPTED

