#!/bin/sh

metaclass1=$(find ./bin -type f -exec grep -HL '__metaclass__ = type' '{}' '+')
future1=$(find ./bin -type f -exec grep -HL 'from __future__ import (absolute_import, division, print_function)' '{}' '+')

metaclass2=$(find ./lib/ansible -path ./lib/ansible/modules -prune \
        -o -path ./lib/ansible/module_utils -prune \
        -o -path ./lib/ansible/module_utils/six/_six.py -prune \
        -o -path ./lib/ansible/compat/selectors/_selectors2.py -prune \
        -o -path ./lib/ansible/utils/module_docs_fragments -prune \
        -o -name '*.py' -type f -size +0c -exec grep -HL '__metaclass__ = type' '{}' '+')

future2=$(find ./lib/ansible -path ./lib/ansible/modules -prune \
        -o -path ./lib/ansible/module_utils -prune \
        -o -path ./lib/ansible/module_utils/six/_six.py -prune \
        -o -path ./lib/ansible/compat/selectors/_selectors2.py -prune \
        -o -path ./lib/ansible/utils/module_docs_fragments -prune \
        -o -name '*.py' -type f -size +0c -exec grep -HL 'from __future__ import (absolute_import, division, print_function)' '{}' '+')

# Eventually we want metaclass3 and future3 to get down to 0
metaclass3=$(find ./lib/ansible/modules -path ./lib/ansible/modules/windows -prune \
        -o -path ./lib/ansible/modules/identity -prune \
        -o -path ./lib/ansible/modules/files -prune \
        -o -path ./lib/ansible/modules/database/proxysql -prune \
        -o -path ./lib/ansible/modules/cloud/ovirt -prune \
        -o -path ./lib/ansible/modules/cloud/openstack -prune \
        -o -path ./lib/ansible/modules/cloud/cloudstack -prune \
        -o -path ./lib/ansible/modules/cloud/amazon -prune \
        -o -path ./lib/ansible/modules/monitoring -prune \
        -o -path ./lib/ansible/modules/network/aos -prune \
        -o -path ./lib/ansible/modules/network/avi -prune \
        -o -path ./lib/ansible/modules/network/cloudengine -prune \
        -o -path ./lib/ansible/modules/network/eos -prune \
        -o -path ./lib/ansible/modules/network/f5 -prune \
        -o -path ./lib/ansible/modules/network/ios -prune \
        -o -path ./lib/ansible/modules/network/junos -prune \
        -o -path ./lib/ansible/modules/network/lenovo -prune \
        -o -path ./lib/ansible/modules/network/netvisor -prune \
        -o -path ./lib/ansible/modules/network/nxos -prune \
        -o -path ./lib/ansible/modules/network/panos -prune \
        -o -path ./lib/ansible/modules/network/vyos -prune \
        -o -name '*.py' -type f -size +0c -exec grep -HL '__metaclass__ = type' '{}' '+')

future3=$(find ./lib/ansible/modules -path ./lib/ansible/modules/windows -prune \
        -o -path ./lib/ansible/modules/identity -prune \
        -o -path ./lib/ansible/modules/files -prune \
        -o -path ./lib/ansible/modules/database/proxysql -prune \
        -o -path ./lib/ansible/modules/cloud/ovirt -prune \
        -o -path ./lib/ansible/modules/cloud/openstack -prune \
        -o -path ./lib/ansible/modules/cloud/cloudstack -prune \
        -o -path ./lib/ansible/modules/cloud/amazon -prune \
        -o -path ./lib/ansible/modules/monitoring -prune \
        -o -path ./lib/ansible/modules/network/aos -prune \
        -o -path ./lib/ansible/modules/network/avi -prune \
        -o -path ./lib/ansible/modules/network/cloudengine -prune \
        -o -path ./lib/ansible/modules/network/eos -prune \
        -o -path ./lib/ansible/modules/network/f5 -prune \
        -o -path ./lib/ansible/modules/network/ios -prune \
        -o -path ./lib/ansible/modules/network/junos -prune \
        -o -path ./lib/ansible/modules/network/lenovo -prune \
        -o -path ./lib/ansible/modules/network/netvisor -prune \
        -o -path ./lib/ansible/modules/network/nxos -prune \
        -o -path ./lib/ansible/modules/network/panos -prune \
        -o -path ./lib/ansible/modules/network/vyos -prune \
        -o -name '*.py' -type f -size +0c -exec egrep -HL 'from __future__ import (?absolute_import, division, print_function)?' '{}' '+')

# Ordered by approximate work, lowest to highest
# Key:
#     [*]: import * fixes
#     [!]: many get_exception fixes
#     [i]: a few get_exception fixes
# (everything below needs boilerplate added)
# Priorities: import*, get_exception, then boilerplate-only
#
# database/proxysql [!]
# network/ios
# network/eos [i]
# network/netvisor
# network/aos [!]
# network/vyos [i]
# identity [!]
# network/lenovo
# network/panos [!]
# network/junos [i]
# files [!]
# network/avi
# network/f5 [*][i]
# monitoring [*][!]
# packaging/os [*][i]
# cloud/cloudstack [*]
# cloud/openstack [*]
# cloud/ovirt
# network/cloudengine [i]
# network/nxos [*][i]
# cloud/amazon [*]

### TODO:
### - module_utils  <=== these are important but not well organized so we'd
###                      have to construct the teset file by file
### - contrib/  <=== Not a priority as these will move to inventory plugins over time


if test -n "$metaclass1" -o -n "$metaclass2" -o -n "$metaclass3" ; then
printf "\n== Missing __metaclass__ = type ==\n"
fi

if test -n "$metaclass1" ; then
  printf "$metaclass1\n"
fi
if test -n "$metaclass2" ; then
  printf "$metaclass2\n"
fi
if test -n "$metaclass3" ; then
  printf "$metaclass3\n"
fi

if test -n "$future1" -o -n "$future2" -o -n "$future3" ; then
  printf "\n== Missing from __future__ import (absolute_import, division, print_function) ==\n"
fi

if test -n "$future1" ; then
  printf "$future1\n"
fi
if test -n "$future2" ; then
  printf "$future2\n"
fi
if test -n "$future3" ; then
  printf "$future3\n"
fi

if test -n "$future1$future2$future3$metaclass1$metaclass2$metaclass3" ; then
  failures=$(printf "$future1$future2$future3$metaclass1$metaclass2$metaclass3"| wc -l)
  failures=$(expr $failures + 2)
  exit $failures
fi
exit 0
