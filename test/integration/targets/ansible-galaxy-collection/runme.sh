#!/usr/bin/env bash

set -eux

# running the test with -vvvv by default since it is not retried
ansible -i ../../inventory -m include_role -a "name=../../ansible-galaxy-collection/" -vvvv "$@" all
