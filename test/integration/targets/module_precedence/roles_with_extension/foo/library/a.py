#!/usr/bin/python
from __future__ import annotations

import json


def main():
    print(json.dumps(dict(changed=False, location="role: foo, a.py")))


if __name__ == "__main__":
    main()
