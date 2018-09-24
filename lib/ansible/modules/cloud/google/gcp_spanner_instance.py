#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    AUTO GENERATED CODE     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file at
#     https://www.github.com/GoogleCloudPlatform/magic-modules
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function
__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ["preview"],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_spanner_instance
description:
    - An isolated set of Cloud Spanner resources on which databases can be hosted.
short_description: Creates a GCP Instance
version_added: 2.7
author: Google Inc. (@googlecloudplatform)
requirements:
    - python >= 2.6
    - requests >= 2.18.4
    - google-auth >= 1.3.0
options:
    state:
        description:
            - Whether the given object should exist in GCP
        choices: ['present', 'absent']
        default: 'present'
    name:
        description:
            - A unique identifier for the instance, which cannot be changed after the instance
              is created. Values are of the form projects/<project>/instances/[a-z][-a-z0-9]*[a-z0-9].
              The final segment of the name must be between 6 and 30 characters in length.
        required: false
    config:
        description:
            - A reference to the instance configuration.
        required: false
    display_name:
        description:
            - The descriptive name for this instance as it appears in UIs. Must be unique per
              project and between 4 and 30 characters in length.
        required: true
    node_count:
        description:
            - The number of nodes allocated to this instance.
        required: false
    labels:
        description:
            - Cloud Labels are a flexible and lightweight mechanism for organizing cloud resources
              into groups that reflect a customer's organizational needs and deployment strategies.
              Cloud Labels can be used to filter collections of resources. They can be used to
              control how resource metrics are aggregated. And they can be used as arguments to
              policy management rules (e.g. route, firewall, load balancing, etc.).
            - 'Label keys must be between 1 and 63 characters long and must conform to the following
              regular expression: `[a-z]([-a-z0-9]*[a-z0-9])?`.'
            - Label values must be between 0 and 63 characters long and must conform to the regular
              expression `([a-z]([-a-z0-9]*[a-z0-9])?)?`.
            - No more than 64 labels can be associated with a given resource.
            - See U(https://goo.gl/xmQnxf) for more information on and examples of labels.
            - 'If you plan to use labels in your own code, please note that additional characters
              may be allowed in the future. And so you are advised to use an internal label representation,
              such as JSON, which doesn''t rely upon specific characters being disallowed. For
              example, representing labels as the string: name + "_" + value would prove problematic
              if we were to allow "_" in a future release.'
            - 'An object containing a list of "key": value pairs.'
            - 'Example: { "name": "wrench", "mass": "1.3kg", "count": "3" }.'
        required: false
extends_documentation_fragment: gcp
'''

EXAMPLES = '''
- name: create a instance
  gcp_spanner_instance:
      name: "test_object"
      display_name: My Spanner Instance
      node_count: 2
      labels:
        cost_center: ti-1700004
      config: regional-us-central1
      project: "test_project"
      auth_kind: "serviceaccount"
      service_account_file: "/tmp/auth.pem"
      state: present
'''

RETURN = '''
    name:
        description:
            - A unique identifier for the instance, which cannot be changed after the instance
              is created. Values are of the form projects/<project>/instances/[a-z][-a-z0-9]*[a-z0-9].
              The final segment of the name must be between 6 and 30 characters in length.
        returned: success
        type: str
    config:
        description:
            - A reference to the instance configuration.
        returned: success
        type: str
    displayName:
        description:
            - The descriptive name for this instance as it appears in UIs. Must be unique per
              project and between 4 and 30 characters in length.
        returned: success
        type: str
    nodeCount:
        description:
            - The number of nodes allocated to this instance.
        returned: success
        type: int
    labels:
        description:
            - Cloud Labels are a flexible and lightweight mechanism for organizing cloud resources
              into groups that reflect a customer's organizational needs and deployment strategies.
              Cloud Labels can be used to filter collections of resources. They can be used to
              control how resource metrics are aggregated. And they can be used as arguments to
              policy management rules (e.g. route, firewall, load balancing, etc.).
            - 'Label keys must be between 1 and 63 characters long and must conform to the following
              regular expression: `[a-z]([-a-z0-9]*[a-z0-9])?`.'
            - Label values must be between 0 and 63 characters long and must conform to the regular
              expression `([a-z]([-a-z0-9]*[a-z0-9])?)?`.
            - No more than 64 labels can be associated with a given resource.
            - See U(https://goo.gl/xmQnxf) for more information on and examples of labels.
            - 'If you plan to use labels in your own code, please note that additional characters
              may be allowed in the future. And so you are advised to use an internal label representation,
              such as JSON, which doesn''t rely upon specific characters being disallowed. For
              example, representing labels as the string: name + "_" + value would prove problematic
              if we were to allow "_" in a future release.'
            - 'An object containing a list of "key": value pairs.'
            - 'Example: { "name": "wrench", "mass": "1.3kg", "count": "3" }.'
        returned: success
        type: dict
'''

################################################################################
# Imports
################################################################################

from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest, replace_resource_dict
import json

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(type='str'),
            config=dict(type='str'),
            display_name=dict(required=True, type='str'),
            node_count=dict(type='int'),
            labels=dict(type='dict')
        )
    )

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/spanner.admin']

    state = module.params['state']

    fetch = fetch_resource(module, self_link(module))
    changed = False

    if fetch:
        if state == 'present':
            if is_different(module, fetch):
                update(module, self_link(module))
                fetch = fetch_resource(module, self_link(module))
                changed = True
        else:
            delete(module, self_link(module))
            fetch = {}
            changed = True
    else:
        if state == 'present':
            fetch = create(module, collection(module))
            changed = True

    fetch.update({'changed': changed})

    module.exit_json(**fetch)


def create(module, link):
    auth = GcpSession(module, 'spanner')
    return return_if_object(module, auth.post(link, resource_to_create(module)))


def update(module, link):
    auth = GcpSession(module, 'spanner')
    return return_if_object(module, auth.patch(link, resource_to_update(module)))


def delete(module, link):
    auth = GcpSession(module, 'spanner')
    return return_if_object(module, auth.delete(link))


def resource_to_request(module):
    request = {
        u'name': module.params.get('name'),
        u'config': module.params.get('config'),
        u'displayName': module.params.get('display_name'),
        u'nodeCount': module.params.get('node_count'),
        u'labels': module.params.get('labels')
    }
    return_vals = {}
    for k, v in request.items():
        if v:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link, allow_not_found=True):
    auth = GcpSession(module, 'spanner')
    return return_if_object(module, auth.get(link), allow_not_found)


def self_link(module):
    return "https://spanner.googleapis.com/v1/projects/{project}/instances/{name}".format(**module.params)


def collection(module):
    return "https://spanner.googleapis.com/v1/projects/{project}/instances".format(**module.params)


def return_if_object(module, response, allow_not_found=False):
    # If not found, return nothing.
    if allow_not_found and response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    result = decode_response(result, module)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def is_different(module, response):
    request = resource_to_request(module)
    response = response_to_hash(module, response)
    request = decode_response(request, module)

    # Remove all output-only from response.
    response_vals = {}
    for k, v in response.items():
        if k in request:
            response_vals[k] = v

    request_vals = {}
    for k, v in request.items():
        if k in response:
            request_vals[k] = v

    return GcpRequest(request_vals) != GcpRequest(response_vals)


# Remove unnecessary properties from the response.
# This is for doing comparisons with Ansible's current parameters.
def response_to_hash(module, response):
    return {
        u'name': response.get(u'name'),
        u'config': response.get(u'config'),
        u'displayName': response.get(u'displayName'),
        u'nodeCount': response.get(u'nodeCount'),
        u'labels': response.get(u'labels')
    }


def resource_to_create(module):
    instance = resource_to_request(module)
    instance['name'] = "projects/{0}/instances/{1}".format(module.params['project'],
                                                           module.params['name'])
    instance['config'] = "projects/{0}/instanceConfigs/{1}".format(module.params['project'],
                                                                   instance['config'])
    return {
        'instanceId': module.params['name'],
        'instance': instance
    }


def resource_to_update(module):
    instance = resource_to_request(module)
    instance['name'] = "projects/{0}/instances/{1}".format(module.params['project'],
                                                           module.params['name'])
    instance['config'] = "projects/{0}/instanceConfigs/{1}".format(module.params['project'],
                                                                   instance['config'])
    return {
        'instance': instance,
        'fieldMask': "'name' ,'config' ,'displayName' ,'nodeCount' ,'labels'"
    }


def decode_response(response, module):
    if not response:
        return response

    if '/operations/' in response['name']:
        return response

    response['name'] = response['name'].split('/')[-1]
    response['config'] = response['config'].split('/')[-1]
    return response


if __name__ == '__main__':
    main()
