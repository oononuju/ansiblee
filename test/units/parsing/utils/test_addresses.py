#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import annotations

import re
import pytest

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.parsing.utils.addresses import parse_address

tests = [
    # IPv4 addresses
    (
        "192.0.2.3",
        ("192.0.2.3", None),
    ),
    (
        "192.0.2.3:23",
        ("192.0.2.3", 23),
    ),
    # IPv6 addresses
    (
        "::",
        ("::", None),
    ),
    (
        "::1",
        ("::1", None),
    ),
    (
        "[::1]:442",
        ("::1", 442),
    ),
    (
        "abcd:ef98:7654:3210:abcd:ef98:7654:3210",
        ("abcd:ef98:7654:3210:abcd:ef98:7654:3210", None),
    ),
    (
        "[abcd:ef98:7654:3210:abcd:ef98:7654:3210]:42",
        ("abcd:ef98:7654:3210:abcd:ef98:7654:3210", 42),
    ),
    (
        "1234:5678:9abc:def0:1234:5678:9abc:def0",
        ("1234:5678:9abc:def0:1234:5678:9abc:def0", None),
    ),
    (
        "1234::9abc:def0:1234:5678:9abc:def0",
        ("1234::9abc:def0:1234:5678:9abc:def0", None),
    ),
    (
        "1234:5678::def0:1234:5678:9abc:def0",
        ("1234:5678::def0:1234:5678:9abc:def0", None),
    ),
    (
        "1234:5678:9abc::1234:5678:9abc:def0",
        ("1234:5678:9abc::1234:5678:9abc:def0", None),
    ),
    (
        "1234:5678:9abc:def0::5678:9abc:def0",
        ("1234:5678:9abc:def0::5678:9abc:def0", None),
    ),
    (
        "1234:5678:9abc:def0:1234::9abc:def0",
        ("1234:5678:9abc:def0:1234::9abc:def0", None),
    ),
    (
        "1234:5678:9abc:def0:1234:5678::def0",
        ("1234:5678:9abc:def0:1234:5678::def0", None),
    ),
    (
        "1234:5678:9abc:def0:1234:5678::",
        ("1234:5678:9abc:def0:1234:5678::", None),
    ),
    (
        "::9abc:def0:1234:5678:9abc:def0",
        ("::9abc:def0:1234:5678:9abc:def0", None),
    ),
    (
        "0:0:0:0:0:ffff:1.2.3.4",
        ("0:0:0:0:0:ffff:1.2.3.4", None),
    ),
    (
        "0:0:0:0:0:0:1.2.3.4",
        ("0:0:0:0:0:0:1.2.3.4", None),
    ),
    (
        "::ffff:1.2.3.4",
        ("::ffff:1.2.3.4", None),
    ),
    (
        "::1.2.3.4",
        ("::1.2.3.4", None),
    ),
    (
        "1234::",
        ("1234::", None),
    ),
    # Hostnames
    (
        "some-host",
        ("some-host", None),
    ),
    (
        "some-host:80",
        ("some-host", 80),
    ),
    (
        "some.host.com:492",
        ("some.host.com", 492),
    ),
    (
        "[some.host.com]:493",
        ("some.host.com", 493),
    ),
    (
        "a-b.3foo_bar.com:23",
        ("a-b.3foo_bar.com", 23),
    ),
    (
        "fóöbär",
        ("fóöbär", None),
    ),
    (
        "fóöbär:32",
        ("fóöbär", 32),
    ),
    (
        "fóöbär.éxàmplê.com:632",
        ("fóöbär.éxàmplê.com", 632),
    ),
]

error_tests = [
    # Various errors
    "",
    "some..host",
    "some.",
    "(example.com]",
    "some-",
    "some-.foo.com",
    "some.-foo.com",
]

range_tests = [
    ("192.0.2.[3:10]", ("192.0.2.[3:10]", None)),
    ("192.0.2.[3:10]:23", ("192.0.2.[3:10]", 23)),
    ("abcd:ef98::7654:[1:9]", ("abcd:ef98::7654:[1:9]", None)),
    ("[abcd:ef98::7654:[6:32]]:2222", ("abcd:ef98::7654:[6:32]", 2222)),
    ("[abcd:ef98::7654:[9ab3:fcb7]]:2222", ("abcd:ef98::7654:[9ab3:fcb7]", 2222)),
    ("fóöb[a:c]r.éxàmplê.com:632", ("fóöb[a:c]r.éxàmplê.com", 632)),
    ("[a:b]foo.com", ("[a:b]foo.com", None)),
    ("foo[a:b].com", ("foo[a:b].com", None)),
    ("foo[a:b]:42", ("foo[a:b]", 42)),
]
range_error_tests = [
    ("foo[a-b]-.com", (None, None)),
    ("foo[a-b]:32", (None, None)),
    ("foo[x-y]", (None, None)),
]

only_valid_ips_tests = [
    ("192.0.2.[3:10]", ("192.0.2.[3:10]", None)),
    ("abcd:ef98::7654:[1:9]", ("abcd:ef98::7654:[1:9]", None)),
]
only_valid_ips_error_tests = [
    "192.168.2.263",
    "2001:0db8:0000:0000:0000:ff00:0042:zzzz",
]


@pytest.mark.parametrize(("test_string", "expected"), tests)
def test_without_ranges(test_string, expected):
    assert parse_address(test_string) == expected


@pytest.mark.parametrize("test_string", error_tests)
def test_without_ranges_error(test_string):
    error_msg = "Not a valid network hostname"
    with pytest.raises(AnsibleError, match=re.escape(error_msg)):
        parse_address(test_string)


@pytest.mark.parametrize(("test_string", "expected"), range_tests)
def test_with_ranges(test_string, expected):
    assert parse_address(test_string, allow_ranges=True) == expected


@pytest.mark.parametrize("test_string", error_tests)
def test_with_ranges_error(test_string):
    error_msg = "Not a valid network hostname"
    with pytest.raises(AnsibleError, match=re.escape(error_msg)):
        parse_address(test_string, allow_ranges=True)


@pytest.mark.parametrize(("test_string", "expected"), only_valid_ips_tests)
def test_only_valid_ips(test_string, expected):
    assert (
        parse_address(test_string, allow_ranges=True, only_valid_ips=True) == expected
    )


@pytest.mark.parametrize("test_string", only_valid_ips_error_tests)
def test_only_valid_ips_error(test_string):
    error_msg = "Not a valid IPv4 or IPv6 address"
    with pytest.raises(AnsibleError, match=re.escape(error_msg)):
        parse_address(test_string, only_valid_ips=True)
