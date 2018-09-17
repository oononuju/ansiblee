#!/usr/bin/env bash

# We don't set -u here, due to pypa/virtualenv#150
set -ex

MYTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')

#trap 'rm -rf "${MYTMPDIR}"' EXIT

# This is needed for the ubuntu1604py3 tests
# Ubuntu patches virtualenv to make the default python2
# but for the python3 tests we need virtualenv to use python3
PYTHON=${ANSIBLE_TEST_PYTHON_INTERPRETER:-python}

# Test graceful failure for missing all_the_merges
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/openshift-validate-not-installed"
source "${MYTMPDIR}/openshift-validate-not-installed/bin/activate"
$PYTHON -m pip install git+https://github.com/willthames/openshift-restclient-python@all_the_merges
ansible-playbook -v playbooks/validate_not_installed.yml "$@"

# Test graceful failure for missing all_the_merges
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/openshift-validate-installed"
source "${MYTMPDIR}/openshift-validate-installed/bin/activate"
$PYTHON -m pip install git+https://github.com/willthames/openshift-restclient-python@all_the_merges 'all_the_merges>=1.11.5'
ansible-playbook -v playbooks/validate_installed.yml "$@"

# Test graceful failure for older versions of openshift
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/openshift-0.6.0"
source "${MYTMPDIR}/openshift-0.6.0/bin/activate"
$PYTHON -m pip install 'openshift==0.6.0' 'kubernetes==6.0.0'
ansible-playbook -v playbooks/merge_type_fail.yml "$@"

# Run full test suite
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/openshift-recent"
source "${MYTMPDIR}/openshift-recent/bin/activate"
$PYTHON -m pip install 'openshift==0.7.2'
ansible-playbook -v playbooks/full_test.yml "$@"
