#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2017-2025 slowtec GmbH <post@slowtec.de>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

SCRIPT_ROOT=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
cd "${SCRIPT_ROOT}"

openssl req -newkey rsa:2048 -nodes -keyout private_key.pem -x509 -out cert.pem
openssl rsa -in private_key.pem -outform DER -out private_key.der
openssl x509 -in cert.pem -outform DER -out cert.der

#curl --etag-compare etag.txt --etag-save etag.txt --remote-name https://curl.se/ca/cacert.pem
#openssl req -new -newkey rsa:4096 -nodes -keyout snakeoil.key -out snakeoil.csr
#openssl x509 -req -sha256 -days 365 -in snakeoil.csr -signkey snakeoil.key -out snakeoil.pem
