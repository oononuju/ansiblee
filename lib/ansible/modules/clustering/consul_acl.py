#!/usr/bin/python
#
# (c) 2015, Steve Gargan <steve.gargan@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: consul_acl
short_description: Manipulate Consul ACL keys and rules
description:
 - Allows the addition, modification and deletion of ACL keys and associated
   rules in a consul cluster via the agent. For more details on using and
   configuring ACLs, see https://www.consul.io/docs/guides/acl.html.
version_added: "2.0"
author:
  - Steve Gargan (@sgargan)
  - Colin Nolan (@colin-nolan)
options:
  mgmt_token:
    description:
      - a management token is required to manipulate the acl lists
  state:
    description:
      - whether the ACL pair should be present or absent
    required: false
    choices: ['present', 'absent']
    default: present
  token_type:
    description:
      - the type of token that should be created, either management or client
    choices: ['client', 'management']
    default: client
  name:
    description:
      - the name that should be associated with the acl key, this is opaque
        to Consul
    required: false
  token:
    description:
      - the token key indentifying an ACL rule set. If generated by consul
        this will be a UUID.
    required: false
  rules:
    description:
      - a list of the rules that should be associated with a given token.
    required: false
  host:
    description:
      - host of the consul agent defaults to localhost
    required: false
    default: localhost
  port:
    description:
      - the port on which the consul agent is running
    required: false
    default: 8500
  scheme:
    description:
      - the protocol scheme on which the consul agent is running
    required: false
    default: http
    version_added: "2.1"
  validate_certs:
    description:
      - whether to verify the tls certificate of the consul agent
    required: false
    default: True
    version_added: "2.1"
requirements:
  - "python >= 2.6"
  - python-consul
  - pyhcl
  - requests
"""

EXAMPLES = """
- name: create an acl token with rules
  consul_acl:
    mgmt_token: 'some_management_acl'
    host: 'consul1.mycluster.io'
    name: 'Foo access'
    rules:
      - key: 'foo'
        policy: read
      - key: 'private/foo'
        policy: deny

- name: create an acl with specific token with both key and service rules
  consul_acl:
    mgmt_token: 'some_management_acl'
    name: 'Foo access'
    token: 'some_client_token'
    rules:
      - key: 'foo'
        policy: read
      - service: ''
        policy: write
      - service: 'secret-'
        policy: deny

- name: remove a token
  consul_acl:
    mgmt_token: 'some_management_acl'
    host: 'consul1.mycluster.io'
    token: '172bd5c8-9fe9-11e4-b1b0-3c15c2c9fd5e'
    state: absent
"""

# FIXME: The return currently changes depending on whether rules are updated or removed. What is actually returned is
# questionable and therefore I will not advertise for use.
RETURN = """ # """


try:
    import consul
    python_consul_installed = True
except ImportError:
    python_consul_installed = False

try:
    import hcl
    pyhcl_installed = True
except ImportError:
    pyhcl_installed = False

from collections import defaultdict
from requests.exceptions import ConnectionError
from ansible.module_utils.basic import to_text, AnsibleModule


RULE_SCOPES = ['agent', 'event', 'key', 'keyring', 'node', 'operator', 'query', 'service', 'session']


def execute(module):
    state = module.params.get('state')
    if state == 'present':
        update_acl(module)
    else:
        remove_acl(module)


def update_acl(module):
    rules = module.params.get('rules')
    token = module.params.get('token')
    token_type = module.params.get('token_type')
    name = module.params.get('name')
    consul = get_consul_api(module)
    changed = False

    rules = decode_rules_as_yml(rules)
    rules_as_hcl = encode_rules_as_hcl_string(rules) if len(rules) > 0 else None

    if token:
        existing_token = load_acl_with_token(consul, token)
        changed = existing_token.rules != rules
        if changed:
            name = name if name is not None else existing_token.name
            token = consul.acl.update(token, name=name, type=token_type, rules=rules_as_hcl)
    else:
        existing_acls_mapped_by_name = dict((acl.name, acl) for acl in decode_acls_as_json(consul.acl.list()))
        if name not in existing_acls_mapped_by_name:
            token = consul.acl.create(name=name, type=token_type, rules=rules_as_hcl)
            changed = True
        else:
            token = existing_acls_mapped_by_name[name].token
            rules = existing_acls_mapped_by_name[name].rules

    module.exit_json(changed=changed, token=token, rules=encode_rules_as_json(rules))


def remove_acl(module):
    token = module.params.get('token')
    consul = get_consul_api(module)
    changed = consul.acl.info(token) is not None
    if changed:
        consul.acl.destroy(token)
    module.exit_json(changed=changed, token=token)


def load_acl_with_token(consul, token):
    """
    Loads the ACL with the given token (token == rule ID).
    :param consul: the consul client
    :param token: the ACL "token"/ID (not name)
    :return: the ACL associated to the given token
    :exception ConsulACLTokenNotFoundException: raised if the given token does not exist
    """
    acl_as_json = consul.acl.info(token)
    if acl_as_json is None:
        raise ConsulACLNotFoundException(token)
    return decode_acl_as_json(acl_as_json)


def encode_rules_as_hcl_string(rules):
    rules_as_hcl = ""
    for rule in rules:
        rules_as_hcl += encode_rule_as_hcl_string(rule)
    return rules_as_hcl


def encode_rule_as_hcl_string(rule):
    if rule.pattern is not None:
        return '%s "%s" {\n  policy = "%s"\n}\n' % (rule.scope, rule.pattern, rule.policy)
    else:
        return '%s = "%s"\n' % (rule.scope, rule.policy)


def decode_rules_as_hcl_string(rules_as_hcl):
    rules_as_hcl = to_text(rules_as_hcl)
    rules_as_json = hcl.loads(rules_as_hcl)
    return decode_rules_as_json(rules_as_json)


def decode_rules_as_json(rules_as_json):
    rules = RuleCollection()
    for scope in rules_as_json:
        if isinstance(rules_as_json[scope], str):
            rules.add(Rule(scope, rules_as_json[scope]))
        else:
            for pattern, policy in rules_as_json[scope].items():
                rules.add(Rule(scope, policy['policy'], pattern))
    return rules


def encode_rules_as_json(rules):
    rules_as_json = defaultdict(dict)
    for rule in rules:
        if rule.pattern is not None:
            assert rule.pattern not in rules_as_json[rule.scope]
            rules_as_json[rule.scope][rule.pattern] = {
                "policy": rule.policy
            }
        else:
            assert rule.scope not in rules_as_json
            rules_as_json[rule.scope] = rule.policy
    return rules_as_json


def decode_rules_as_yml(rules_as_yml):
    rules = RuleCollection()
    if rules_as_yml:
        for rule_as_yml in rules_as_yml:
            rule_added = False
            for scope in RULE_SCOPES:
                if scope in rule_as_yml:
                    if rule_as_yml[scope] is None:
                        raise ValueError("Rule for '%s' does not have a value associated to the scope" % scope)
                    policy = rule_as_yml["policy"] if "policy" in rule_as_yml else rule_as_yml[scope]
                    pattern = rule_as_yml[scope] if "policy" in rule_as_yml else None
                    rules.add(Rule(scope, policy, pattern))
                    rule_added = True
                    break
            if not rule_added:
                raise ValueError("A rule requires one of %s and a policy." % ('/'.join(RULE_SCOPES)))
    return rules


def decode_acl_as_json(acl_as_json):
    rules_as_hcl = acl_as_json["Rules"]
    rules = decode_rules_as_hcl_string(acl_as_json["Rules"]) if rules_as_hcl.strip() != "" else RuleCollection()
    return ACL(
        rules=rules,
        token_type=acl_as_json["Type"],
        token=acl_as_json["ID"],
        name=acl_as_json["Name"]
    )


def decode_acls_as_json(acls_as_json):
    return [decode_acl_as_json(acl_as_json) for acl_as_json in acls_as_json]


class ConsulACLNotFoundException(Exception):
    """
    Exception raised if an ACL with is not found.
    """


class ACL:
    def __init__(self, rules, token_type, token, name):
        self.rules = rules
        self.token_type = token_type
        self.token = token
        self.name = name

    def __eq__(self, other):
        return other \
            and isinstance(other, self.__class__) \
            and self.rules == other.rules \
            and self.token_type == other.token_type \
            and self.token == other.token \
            and self.name == other.name

    def __hash__(self):
        return hash(self.rules) ^ hash(self.token_type) ^ hash(self.token) ^ hash(self.name)


class Rule:
    def __init__(self, scope, policy, pattern=None):
        self.scope = scope
        self.policy = policy
        self.pattern = pattern

    def __eq__(self, other):
        return other \
            and isinstance(other, self.__class__) \
            and self.scope == other.scope \
            and self.policy == other.policy \
            and self.pattern == other.pattern

    def __hash__(self):
        return (hash(self.scope) ^ hash(self.policy)) ^ hash(self.pattern)

    def __str__(self):
        return encode_rule_as_hcl_string(self)


class RuleCollection:
    def __init__(self):
        self._rules = {}
        for scope in RULE_SCOPES:
            self._rules[scope] = {}

    def __iter__(self):
        all_rules = []
        for scope, pattern_keyed_rules in self._rules.items():
            for pattern, rule in pattern_keyed_rules.items():
                all_rules.append(rule)
        return iter(all_rules)

    def __len__(self):
        count = 0
        for scope in RULE_SCOPES:
            count += len(self._rules[scope])
        return count

    def __eq__(self, other):
        return other \
            and isinstance(other, self.__class__) \
            and set(self) == set(other)

    def __str__(self):
        return encode_rules_as_hcl_string(self)

    def add(self, rule):
        if rule.pattern in self._rules[rule.scope]:
            patten_info = " and pattern '%s'" % rule.pattern if rule.pattern is not None else ""
            raise ValueError("Duplicate rule for scope '%s'%s" % (rule.scope, patten_info))
        self._rules[rule.scope][rule.pattern] = rule


def get_consul_api(module):
    token = module.params.get('mgmt_token')
    if token is None:
        token = module.params.get('token')
    assert token is not None, "Expecting the management token to alway be set"
    return consul.Consul(host=module.params.get('host'),
                         port=module.params.get('port'),
                         scheme=module.params.get('scheme'),
                         verify=module.params.get('validate_certs'),
                         token=token)


def check_dependencies(module):
    if not python_consul_installed:
        module.fail_json(msg="python-consul required for this module. "
                             "See: http://python-consul.readthedocs.org/en/latest/#installation")

    if not pyhcl_installed:
        module.fail_json(msg="pyhcl required for this module. "
                             "See: https://pypi.python.org/pypi/pyhcl")


def main():
    argument_spec = dict(
        mgmt_token=dict(required=True, no_log=True),
        host=dict(default='localhost'),
        scheme=dict(required=False, default='http'),
        validate_certs=dict(required=False, type='bool', default=True),
        name=dict(required=False),
        port=dict(default=8500, type='int'),
        rules=dict(default=None, required=False, type='list'),
        state=dict(default='present', choices=['present', 'absent']),
        token=dict(required=False, no_log=True),
        token_type=dict(
            required=False, choices=['client', 'management'], default='client')
    )
    module = AnsibleModule(argument_spec, supports_check_mode=False)

    check_dependencies(module)

    try:
        execute(module)
    except ConnectionError as e:
        module.fail_json(msg='Could not connect to consul agent at %s:%s, error was %s' % (
            module.params.get('host'), module.params.get('port'), str(e)))


if __name__ == '__main__':
    main()
