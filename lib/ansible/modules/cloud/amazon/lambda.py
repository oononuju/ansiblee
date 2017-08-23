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


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: lambda
short_description: Manage AWS Lambda functions
description:
     - Allows for the management of Lambda functions.
version_added: '2.2'
requirements: [ boto3 ]
options:
  name:
    description:
      - The name you want to assign to the function you are uploading. Cannot be changed.
    required: true
  state:
    description:
      - Create or delete Lambda function
    default: present
    choices: [ 'present', 'absent' ]
  runtime:
    description:
      - The runtime environment for the Lambda function you are uploading. Required when creating a function. Use parameters as described in boto3 docs.
        Current example runtime environments are nodejs, nodejs4.3, java8 or python2.7
      - Required when C(state=present)
  role:
    description:
      - The Amazon Resource Name (ARN) of the IAM role that Lambda assumes when it executes your function to access any other Amazon Web Services (AWS)
        resources. You may use the bare ARN if the role belongs to the same AWS account.
      - Required when C(state=present)
  handler:
    description:
      - The function within your code that Lambda calls to begin execution
    default: null
  zip_file:
    description:
      - A .zip file containing your deployment package
      - If C(state=present) then either zip_file or s3_bucket must be present.
    required: false
    default: null
    aliases: [ 'src' ]
  s3_bucket:
    description:
      - Amazon S3 bucket name where the .zip file containing your deployment package is stored
      - If C(state=present) then either zip_file or s3_bucket must be present.
      - s3_bucket and s3_key are required together
    required: false
    default: null
  s3_key:
    description:
      - The Amazon S3 object (the deployment package) key name you want to upload
      - s3_bucket and s3_key are required together
    required: false
    default: null
  s3_object_version:
    description:
      - The Amazon S3 object (the deployment package) version you want to upload.
    required: false
    default: null
  description:
    description:
      - A short, user-defined function description. Lambda does not use this value. Assign a meaningful description as you see fit.
    required: false
    default: null
  timeout:
    description:
      - The function execution time at which Lambda should terminate the function.
    required: false
    default: 3
  memory_size:
    description:
      - The amount of memory, in MB, your Lambda function is given
    required: false
    default: 128
  vpc_subnet_ids:
    description:
      - List of subnet IDs to run Lambda function in. Use this option if you need to access resources in your VPC. Leave empty if you don't want to run
        the function in a VPC.
    required: false
    default: None
  vpc_security_group_ids:
    description:
      - List of VPC security group IDs to associate with the Lambda function. Required when vpc_subnet_ids is used.
    required: false
    default: None
  environment_variables:
    description:
      - A dictionary of environment variables the Lambda function is given.
    required: false
    default: None
    aliases: [ 'environment' ]
    version_added: "2.3"
  dead_letter_arn:
    description:
      - The parent object that contains the target Amazon Resource Name (ARN) of an Amazon SQS queue or Amazon SNS topic.
    required: false
    default: None
    version_added: "2.3"
author:
    - 'Steyn Huizinga (@steynovich)'
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Create Lambda functions
tasks:
- name: looped creation
  lambda:
    name: '{{ item.name }}'
    state: present
    zip_file: '{{ item.zip_file }}'
    runtime: 'python2.7'
    role: 'arn:aws:iam::987654321012:role/lambda_basic_execution'
    handler: 'hello_python.my_handler'
    vpc_subnet_ids:
    - subnet-123abcde
    - subnet-edcba321
    vpc_security_group_ids:
    - sg-123abcde
    - sg-edcba321
    environment_variables: '{{ item.env_vars }}'
  with_items:
    - name: HelloWorld
      zip_file: hello-code.zip
      env_vars:
        key1: "first"
        key2: "second"
    - name: ByeBye
      zip_file: bye-code.zip
      env_vars:
        key1: "1"
        key2: "2"

# Basic Lambda function deletion
tasks:
- name: Delete Lambda functions HelloWorld and ByeBye
  lambda:
    name: '{{ item }}'
    state: absent
  with_items:
    - HelloWorld
    - ByeBye
'''

RETURN = '''
output:
  description: the data returned by get_function in boto3
  returned: success
  type: dict
  sample:
    'code':
      {
        'location': 'an S3 URL',
        'repository_type': 'S3',
      }
    'configuration':
      {
        'function_name': 'string',
        'function_arn': 'string',
        'runtime': 'nodejs',
        'role': 'string',
        'handler': 'string',
        'code_size': 123,
        'description': 'string',
        'timeout': 123,
        'memory_size': 123,
        'last_modified': 'string',
        'code_sha256': 'string',
        'version': 'string',
      }
'''

from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import get_aws_connection_info, boto3_conn, camel_dict_to_snake_dict
import base64
import hashlib
import traceback

try:
    from botocore.exceptions import ClientError, ValidationError, ParamValidationError
except ImportError:
    pass  # protected by AnsibleAWSModule


def get_account_id(module, region=None, endpoint=None, **aws_connect_kwargs):
    """return the account id we are currently working on

    get_account_id tries too find out the account that we are working
    on.  It's not guaranteed that this will be easy so we try in
    several different ways.  Giving either IAM or STS privilages to
    the account should be enough to permit this.
    """
    try:
        sts_client = boto3_conn(module, conn_type='client', resource='sts',
                                region=region, endpoint=endpoint, **aws_connect_kwargs)
        account_id = sts_client.get_caller_identity().get('Account')
    except ClientError:
        try:
            iam_client = boto3_conn(module, conn_type='client', resource='iam',
                                    region=region, endpoint=endpoint, **aws_connect_kwargs)
            account_id = iam_client.get_user()['User']['Arn'].split(':')[4]
        except Exception as e:
            module.fail_json_aws(e, msg="getting account information")
    return account_id


def get_current_function(connection, function_name, qualifier=None):
    try:
        if qualifier is not None:
            return connection.get_function(FunctionName=function_name, Qualifier=qualifier)
        return connection.get_function(FunctionName=function_name)
    except ClientError:
        return None


def sha256sum(filename):
    hasher = hashlib.sha256()
    with open(filename, 'rb') as f:
        hasher.update(f.read())

    code_hash = hasher.digest()
    code_b64 = base64.b64encode(code_hash)
    hex_digest = code_b64.decode('utf-8')

    return hex_digest


def main():
    argument_spec = dict(
        name=dict(required=True),
        state=dict(default='present', choices=['present', 'absent']),
        runtime=dict(),
        role=dict(),
        handler=dict(),
        zip_file=dict(aliases=['src']),
        s3_bucket=dict(),
        s3_key=dict(),
        s3_object_version=dict(),
        description=dict(default=''),
        timeout=dict(type='int', default=3),
        memory_size=dict(type='int', default=128),
        vpc_subnet_ids=dict(type='list'),
        vpc_security_group_ids=dict(type='list'),
        environment_variables=dict(type='dict'),
        dead_letter_arn=dict(),
    )

    mutually_exclusive = [['zip_file', 's3_key'],
                          ['zip_file', 's3_bucket'],
                          ['zip_file', 's3_object_version']]

    required_together = [['s3_key', 's3_bucket'],
                         ['vpc_subnet_ids', 'vpc_security_group_ids']]

    required_if = [['state', 'present', ['runtime', 'handler', 'role']]]

    module = AnsibleAWSModule(argument_spec=argument_spec,
                              supports_check_mode=True,
                              mutually_exclusive=mutually_exclusive,
                              required_together=required_together,
                              required_if=required_if)

    name = module.params.get('name')
    state = module.params.get('state').lower()
    runtime = module.params.get('runtime')
    role = module.params.get('role')
    handler = module.params.get('handler')
    s3_bucket = module.params.get('s3_bucket')
    s3_key = module.params.get('s3_key')
    s3_object_version = module.params.get('s3_object_version')
    zip_file = module.params.get('zip_file')
    description = module.params.get('description')
    timeout = module.params.get('timeout')
    memory_size = module.params.get('memory_size')
    vpc_subnet_ids = module.params.get('vpc_subnet_ids')
    vpc_security_group_ids = module.params.get('vpc_security_group_ids')
    environment_variables = module.params.get('environment_variables')
    dead_letter_arn = module.params.get('dead_letter_arn')

    check_mode = module.check_mode
    changed = False

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    if not region:
        module.fail_json(msg='region must be specified')

    try:
        client = boto3_conn(module, conn_type='client', resource='lambda',
                            region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except (ClientError, ValidationError) as e:
        module.fail_json_aws(e, msg="Trying to connect to AWS")

    if state == 'present':
        if role.startswith('arn:aws:iam'):
            role_arn = role
        else:
            # get account ID and assemble ARN
            account_id = get_account_id(module, region=region, endpoint=ec2_url, **aws_connect_kwargs)
            role_arn = 'arn:aws:iam::{0}:role/{1}'.format(account_id, role)

    # Get function configuration if present, False otherwise
    current_function = get_current_function(client, name)

    # Update existing Lambda function
    if state == 'present' and current_function:

        # Get current state
        current_config = current_function['Configuration']
        current_version = None

        # Update function configuration
        func_kwargs = {'FunctionName': name}

        # Update configuration if needed
        if role_arn and current_config['Role'] != role_arn:
            func_kwargs.update({'Role': role_arn})
        if handler and current_config['Handler'] != handler:
            func_kwargs.update({'Handler': handler})
        if description and current_config['Description'] != description:
            func_kwargs.update({'Description': description})
        if timeout and current_config['Timeout'] != timeout:
            func_kwargs.update({'Timeout': timeout})
        if memory_size and current_config['MemorySize'] != memory_size:
            func_kwargs.update({'MemorySize': memory_size})
        if (environment_variables is not None) and (current_config.get(
                'Environment', {}).get('Variables', {}) != environment_variables):
            func_kwargs.update({'Environment': {'Variables': environment_variables}})
        if dead_letter_arn is not None:
            if current_config.get('DeadLetterConfig'):
                if current_config['DeadLetterConfig']['TargetArn'] != dead_letter_arn:
                    func_kwargs.update({'DeadLetterConfig': {'TargetArn': dead_letter_arn}})
            else:
                if dead_letter_arn != "":
                    func_kwargs.update({'DeadLetterConfig': {'TargetArn': dead_letter_arn}})

        # Check for unsupported mutation
        if current_config['Runtime'] != runtime:
            module.fail_json(msg='Cannot change runtime. Please recreate the function')

        # If VPC configuration is desired
        if vpc_subnet_ids or vpc_security_group_ids:
            if  vpc_subnet_ids is None or len(vpc_subnet_ids) == 0 or vpc_security_group_ids is None or len(vpc_security_group_ids) == 0:
                module.fail_json(msg='vpc connectivity requires at least one security group and one subnet')

            if 'VpcConfig' in current_config:
                # Compare VPC config with current config
                current_subnet_ids = current_config['VpcConfig']['SubnetIds']
                current_security_group_ids = current_config['VpcConfig']['SecurityGroupIds']

                subnets_changed = sorted(vpc_subnet_ids) != sorted(current_subnet_ids)
                security_groups_changed = sorted(vpc_security_group_ids) != sorted(current_security_group_ids)

            if 'VpcConfig' not in current_config or subnets_changed or security_groups_changed:
                new_vpc_config = {'SubnetIds': vpc_subnet_ids,
                                  'SecurityGroupIds': vpc_security_group_ids}
                func_kwargs.update({'VpcConfig': new_vpc_config})
        else:
            # No VPC configuration is desired, assure VPC config is empty when
            # present in current config
            if ('VpcConfig' in current_config and'VpcId' in current_config['VpcConfig'] and
                    current_config['VpcConfig']['VpcId'] != ''):
                func_kwargs.update({'VpcConfig': {'SubnetIds': [], 'SecurityGroupIds': []}})

        # Upload new configuration if configuration has changed
        if len(func_kwargs) > 1:
            try:
                if not check_mode:
                    response = client.update_function_configuration(**func_kwargs)
                    current_version = response['Version']
                changed = True
            except (ParamValidationError, ClientError) as e:
                module.fail_json_aws(e, msg="Trying to update lambda configuration")

        # Update code configuration
        code_kwargs = {'FunctionName': name, 'Publish': True}

        # Update S3 location
        if s3_bucket and s3_key:
            # If function is stored on S3 always update
            code_kwargs.update({'S3Bucket': s3_bucket, 'S3Key': s3_key})

            # If S3 Object Version is given
            if s3_object_version:
                code_kwargs.update({'S3ObjectVersion': s3_object_version})

        # Compare local checksum, update remote code when different
        elif zip_file:
            local_checksum = sha256sum(zip_file)
            remote_checksum = current_config['CodeSha256']

            # Only upload new code when local code is different compared to the
            # remote code
            if local_checksum != remote_checksum:
                try:
                    with open(zip_file, 'rb') as f:
                        encoded_zip = f.read()
                    code_kwargs.update({'ZipFile': encoded_zip})
                except IOError as e:
                    module.fail_json(msg=str(e), exception=traceback.format_exc())

        # Upload new code if needed (e.g. code checksum has changed)
        if len(code_kwargs) > 2:
            try:
                if not check_mode:
                    response = client.update_function_code(**code_kwargs)
                    current_version = response['Version']
                changed = True
            except (ParamValidationError, ClientError) as e:
                module.fail_json_aws(e, msg="Trying to upload new code")

        # Describe function code and configuration
        response = get_current_function(client, name, qualifier=current_version)
        if not response:
            module.fail_json(msg='Unable to get function information after updating')

        # We're done
        module.exit_json(changed=changed, **camel_dict_to_snake_dict(response))

    # Function doesn't exists, create new Lambda function
    elif state == 'present':
        if s3_bucket and s3_key:
            # If function is stored on S3
            code = {'S3Bucket': s3_bucket,
                    'S3Key': s3_key}
            if s3_object_version:
                code.update({'S3ObjectVersion': s3_object_version})
        elif zip_file:
            # If function is stored in local zipfile
            try:
                with open(zip_file, 'rb') as f:
                    zip_content = f.read()

                code = {'ZipFile': zip_content}
            except IOError as e:
                module.fail_json(msg=str(e), exception=traceback.format_exc())

        else:
            module.fail_json(msg='Either S3 object or path to zipfile required')

        func_kwargs = {'FunctionName': name,
                       'Publish': True,
                       'Runtime': runtime,
                       'Role': role_arn,
                       'Code': code,
                       'Timeout': timeout,
                       'MemorySize': memory_size,
                       }

        if description is not None:
            func_kwargs.update({'Description': description})

        if handler is not None:
            func_kwargs.update({'Handler': handler})

        if environment_variables:
            func_kwargs.update({'Environment': {'Variables': environment_variables}})

        if dead_letter_arn:
            func_kwargs.update({'DeadLetterConfig': {'TargetArn': dead_letter_arn}})

        # If VPC configuration is given
        if vpc_subnet_ids or vpc_security_group_ids:
            if  vpc_subnet_ids is None or len(vpc_subnet_ids) == 0 or vpc_security_group_ids is None or len(vpc_security_group_ids) == 0:
                module.fail_json(msg='vpc connectivity requires at least one security group and one subnet')

            func_kwargs.update({'VpcConfig': {'SubnetIds': vpc_subnet_ids,
                                              'SecurityGroupIds': vpc_security_group_ids}})

        # Finally try to create function
        try:
            if not check_mode:
                response = client.create_function(**func_kwargs)
                current_version = response['Version']
            changed = True
        except (ParamValidationError, ClientError) as e:
            module.fail_json_aws(e, msg="Trying to create function")

        response = get_current_function(client, name, qualifier=current_version)
        if not response:
            module.fail_json(msg='Unable to get function information after creating')
        module.exit_json(changed=changed, **camel_dict_to_snake_dict(response))

    # Delete existing Lambda function
    if state == 'absent' and current_function:
        try:
            if not check_mode:
                client.delete_function(FunctionName=name)
            changed = True
        except (ParamValidationError, ClientError) as e:
            module.fail_json_aws(e, msg="Trying to delete Lambda function")

        module.exit_json(changed=changed)

    # Function already absent, do nothing
    elif state == 'absent':
        module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
