#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ibm_ssl_certificate
short_description: Configure IBM Cloud 'ibm_ssl_certificate' resource

version_added: "2.8"

description:
    - Create, update or destroy an IBM Cloud 'ibm_ssl_certificate' resource

requirements:
    - IBM-Cloud terraform-provider-ibm v1.5.2
    - Terraform v0.12.20

options:
    order_approver_email_address:
        description:
            - (Required for new resource) Email address of the approver
        required: False
        type: str
    billing_contact_same_as_technical_flag:
        description:
            - billing contact
        required: False
        type: bool
        default: False
    technical_contact:
        description:
            - (Required for new resource) Technical contact info
        required: False
        type: list
        elements: dict
    billing_contact:
        description:
            - None
        required: False
        type: list
        elements: dict
    validity_months:
        description:
            - (Required for new resource) vslidity of the ssl certificate in month
        required: False
        type: int
    administrative_address_same_as_organization_flag:
        description:
            - administrative address same as organization flag
        required: False
        type: bool
        default: False
    organization_information:
        description:
            - (Required for new resource) Organization information
        required: False
        type: list
        elements: dict
    renewal_flag:
        description:
            - Renewal flag
        required: False
        type: bool
        default: True
    administrative_contact_same_as_technical_flag:
        description:
            - Administrative contact same as technical flag
        required: False
        type: bool
        default: False
    billing_address_same_as_organization_flag:
        description:
            - billing address same as organization flag
        required: False
        type: bool
        default: False
    administrative_contact:
        description:
            - None
        required: False
        type: list
        elements: dict
    server_count:
        description:
            - (Required for new resource) Server count
        required: False
        type: int
    server_type:
        description:
            - (Required for new resource) server type
        required: False
        type: str
    certificate_signing_request:
        description:
            - (Required for new resource) certificate signing request info
        required: False
        type: str
    ssl_type:
        description:
            - (Required for new resource) ssl type
        required: False
        type: str
    technical_contact_same_as_org_address_flag:
        description:
            - Technical contact same as org address flag
        required: False
        type: bool
        default: False
    id:
        description:
            - (Required when updating or destroying existing resource) IBM Cloud Resource ID.
        required: False
        type: str
    state:
        description:
            - State of resource
        choices:
            - available
            - absent
        default: available
        required: False
    iaas_classic_username:
        description:
            - (Required when generation = 1) The IBM Cloud Classic
              Infrastructure (SoftLayer) user name. This can also be provided
              via the environment variable 'IAAS_CLASSIC_USERNAME'.
        required: False
    iaas_classic_api_key:
        description:
            - (Required when generation = 1) The IBM Cloud Classic
              Infrastructure API key. This can also be provided via the
              environment variable 'IAAS_CLASSIC_API_KEY'.
        required: False
    region:
        description:
            - The IBM Cloud region where you want to create your
              resources. If this value is not specified, us-south is
              used by default. This can also be provided via the
              environment variable 'IC_REGION'.
        default: us-south
        required: False
    ibmcloud_api_key:
        description:
            - The IBM Cloud API key to authenticate with the IBM Cloud
              platform. This can also be provided via the environment
              variable 'IC_API_KEY'.
        required: True

author:
    - Jay Carman (@jaywcarman)
'''

# Top level parameter keys required by Terraform module
TL_REQUIRED_PARAMETERS = [
    ('order_approver_email_address', 'str'),
    ('technical_contact', 'list'),
    ('validity_months', 'int'),
    ('organization_information', 'list'),
    ('server_count', 'int'),
    ('server_type', 'str'),
    ('certificate_signing_request', 'str'),
    ('ssl_type', 'str'),
]

# All top level parameter keys supported by Terraform module
TL_ALL_PARAMETERS = [
    'order_approver_email_address',
    'billing_contact_same_as_technical_flag',
    'technical_contact',
    'billing_contact',
    'validity_months',
    'administrative_address_same_as_organization_flag',
    'organization_information',
    'renewal_flag',
    'administrative_contact_same_as_technical_flag',
    'billing_address_same_as_organization_flag',
    'administrative_contact',
    'server_count',
    'server_type',
    'certificate_signing_request',
    'ssl_type',
    'technical_contact_same_as_org_address_flag',
]

# define available arguments/parameters a user can pass to the module
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.ibmcloud_utils.ibmcloud import Terraform, ibmcloud_terraform
module_args = dict(
    order_approver_email_address=dict(
        required=False,
        type='str'),
    billing_contact_same_as_technical_flag=dict(
        default=False,
        type='bool'),
    technical_contact=dict(
        required=False,
        elements='',
        type='list'),
    billing_contact=dict(
        required=False,
        elements='',
        type='list'),
    validity_months=dict(
        required=False,
        type='int'),
    administrative_address_same_as_organization_flag=dict(
        default=False,
        type='bool'),
    organization_information=dict(
        required=False,
        elements='',
        type='list'),
    renewal_flag=dict(
        default=True,
        type='bool'),
    administrative_contact_same_as_technical_flag=dict(
        default=False,
        type='bool'),
    billing_address_same_as_organization_flag=dict(
        default=False,
        type='bool'),
    administrative_contact=dict(
        required=False,
        elements='',
        type='list'),
    server_count=dict(
        required=False,
        type='int'),
    server_type=dict(
        required=False,
        type='str'),
    certificate_signing_request=dict(
        required=False,
        type='str'),
    ssl_type=dict(
        required=False,
        type='str'),
    technical_contact_same_as_org_address_flag=dict(
        default=False,
        type='bool'),
    id=dict(
        required=False,
        type='str'),
    state=dict(
        type='str',
        required=False,
        default='available',
        choices=(['available', 'absent'])),
    iaas_classic_username=dict(
        type='str',
        no_log=True,
        fallback=(env_fallback, ['IAAS_CLASSIC_USERNAME']),
        required=False),
    iaas_classic_api_key=dict(
        type='str',
        no_log=True,
        fallback=(env_fallback, ['IAAS_CLASSIC_API_KEY']),
        required=False),
    region=dict(
        type='str',
        fallback=(env_fallback, ['IC_REGION']),
        default='us-south'),
    ibmcloud_api_key=dict(
        type='str',
        no_log=True,
        fallback=(env_fallback, ['IC_API_KEY']),
        required=True)
)


def run_module():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # New resource required arguments checks
    missing_args = []
    if module.params['id'] is None:
        for arg, _ in TL_REQUIRED_PARAMETERS:
            if module.params[arg] is None:
                missing_args.append(arg)
        if missing_args:
            module.fail_json(msg=(
                "missing required arguments: " + ", ".join(missing_args)))

    result = ibmcloud_terraform(
        resource_type='ibm_ssl_certificate',
        tf_type='resource',
        parameters=module.params,
        ibm_provider_version='1.5.2',
        tl_required_params=TL_REQUIRED_PARAMETERS,
        tl_all_params=TL_ALL_PARAMETERS)

    if result['rc'] > 0:
        module.fail_json(
            msg=Terraform.parse_stderr(result['stderr']), **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
