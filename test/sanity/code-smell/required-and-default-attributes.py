from __future__ import annotations

import re
import sys
import ast


class CallVisitor(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path

    def visit_Call(self, node):
        if getattr(node.func, "id", "").endswith("FieldAttribute"):
            count = 0
            for kw in node.keywords:
                if kw.arg in ("default", "required"):
                    count += 1
            if count > 1:
                print(
                    f"{self.path}:{node.lineno}:{node.col_offset}: use only one of `default` or `required` with `{node.func.id}`"
                )


def main():
    for path in sys.argv[1:] or sys.stdin.read().splitlines():
        with open(path, "r") as path_fd:
            tree = ast.parse(path_fd.read())
            CallVisitor(path).visit(tree)


if __name__ == "__main__":
    main()
