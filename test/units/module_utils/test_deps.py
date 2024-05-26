# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Alexei Znamensky <russoz@gmail.com>
# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible.module_utils import deps

def test_deps():
    with deps.declare("re"):
        import re

    deps.validate()

    ctx = DependencyCtxMgr("POTATOES", "Potatoes must be installed")
    with ctx:
        import potatoes_that_will_never_be_there  # noqa: F401, pylint: disable=unused-import
    print("POTATOES: ctx.text={0}".format(ctx.text))
    assert ctx.text == "Potatoes must be installed"
    assert not ctx.has_it

    ctx = DependencyCtxMgr("POTATOES2")
    with ctx:
        import potatoes_that_will_never_be_there_again  # noqa: F401, pylint: disable=unused-import
    assert not ctx.has_it
    print("POTATOES2: ctx.text={0}".format(ctx.text))
    assert ctx.text.startswith("No module named")
    assert "potatoes_that_will_never_be_there_again" in ctx.text

    ctx = DependencyCtxMgr("TYPING")
    with ctx:
        import sys  # noqa: F401, pylint: disable=unused-import
    assert ctx.has_it
