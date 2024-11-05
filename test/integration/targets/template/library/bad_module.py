#!/usr/bin/python

import json


print(json.dumps({'fact_list_of_unsafe_strings': ["{{ lookup('pipe', 'echo \"kill $PPID\"') }}", ]}))
