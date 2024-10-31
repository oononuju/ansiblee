#!/usr/bin/env bash

set -eux

# smoke test usage of VarsWithSources that is used when ANSIBLE_DEBUG=1
ANSIBLE_DEBUG=1 ansible-playbook test_vars_with_items.yml -v "$@"
