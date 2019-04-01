#!/bin/bash
STRING="${1}"
SALT=$(openssl rand -hex 8)
K=$(openssl rand -hex 12)
ENCRYPTED=$(echo "${STRING}" | openssl enc -aes256 -a -A -S "${SALT}" -k "${K}")
echo "Encrypted String: ${ENCRYPTED}"
echo "Salt: ${SALT} | Passphrase: ${K}"

