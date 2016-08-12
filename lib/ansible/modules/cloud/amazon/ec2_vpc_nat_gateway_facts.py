#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: ec2_vpc_nat_gateway_facts
short_description: Retrieves AWS VPC Managed Nat Gateway details using AWS methods.
description:
  - Gets various details related to AWS VPC Managed Nat Gateways
version_added: "2.2"
requirements: [ boto3 ]
options:
  nat_gateway_ids:
    description:
      - Get details of specific nat gateway IDs
    required: false
    default: None
  filters:
    description:
      - A dict of filters to apply. Each dict item consists of a filter key and a filter value.
        See U(http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNatGateways.html)
        for possible filters.
    required: false
    default: None
author: Karen Cheng(@Etherdaemon)
extends_documentation_fragment:
  - aws
  - ec2
'''

EXAMPLES = '''
# Simple example of listing all nat gateways
- name: List all managed nat gateways in ap-southeast-2
  ec2_vpc_nat_gateway_facts:
    region: ap-southeast-2
  register: all_ngws

- name: Debugging the result
  debug:
    msg: "{{ all_ngws.result }}"

- name: Get details on specific nat gateways
  ec2_vpc_nat_gateway_facts:
    nat_gateway_ids:
      - nat-1234567891234567
      - nat-7654321987654321
    region: ap-southeast-2
  register: specific_ngws

- name: Get all nat gateways with specific filters
  ec2_vpc_nat_gateway_facts:
    region: ap-southeast-2
    filters:
      state: ['pending']
  register: pending_ngws

- name: Get nat gateways with specific filter
  ec2_vpc_nat_gateway_facts:
    region: ap-southeast-2
    filters:
      subnet-id: subnet-12345678
      state: ['available']
  register: existing_nat_gateways
'''

RETURN = '''
result:
  description: The result of the describe.
    See http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_nat_gateways for the response.
  returned: success
  type: list
'''

try:
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import time
import json


def date_handler(obj):
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def get_nat_gateways(client, module, nat_gateway_id=None):
    params = dict()

    if module.params.get('filters'):
        params['Filter'] = []
        for key, value in module.params.get('filters').iteritems():
            temp_dict = dict()
            temp_dict['Name'] = key
            if isinstance(value, basestring):
                temp_dict['Values'] = [value]
            else:
                temp_dict['Values'] = value
            params['Filter'].append(temp_dict)
    if module.params.get('nat_gateway_ids'):
        params['NatGatewayIds'] = module.params.get('nat_gateway_ids')

    try:
        result = json.loads(json.dumps(client.describe_nat_gateways(**params), default=date_handler))
    except Exception as e:
        module.fail_json(msg=str(e.message))

    return result['NatGateways']


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        filters=dict(default=None, type='dict'),
        nat_gateway_ids=dict(default=None, type='list'),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec,)

    # Validate Requirements
    if not HAS_BOTO3:
        module.fail_json(msg='botocore/boto3 is required.')

    try:
        region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)
        if region:
            connection = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_params)
        else:
            module.fail_json(msg="region must be specified")
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg=str(e))

    results = get_nat_gateways(connection, module)

    module.exit_json(result=results)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
