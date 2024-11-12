#!/usr/bin/python
from __future__ import annotations

import json


print(json.dumps({'fact_list_of_unsafe_strings': ["{{ lookup('pipe', 'echo \"kill $PPID\"') }}", ]}))
