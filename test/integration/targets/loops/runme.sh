#!/usr/bin/env bash

set -ux

# test with_ vs loop unsafe/safe as previous uses lookups
ansible-playbook -i ../../inventory unsafe.yml "$@"

# run rest of tests as role
ANSIBLE_ROLES_PATH=../ ansible-playbook -i ../../inventory runme.yml -v "$@"

