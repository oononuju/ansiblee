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

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ["preview"], 'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_pubsub_topic
description:
- A named resource to which messages are sent by publishers.
short_description: Creates a GCP Topic
version_added: 2.6
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  state:
    description:
    - Whether the given object should exist in GCP
    choices:
    - present
    - absent
    default: present
  name:
    description:
    - Name of the topic.
    required: true
  labels:
    description:
    - A set of key/value label pairs to assign to this Topic.
    required: false
    version_added: 2.8
extends_documentation_fragment: gcp
notes:
- 'API Reference: U(https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics)'
- 'Managing Topics: U(https://cloud.google.com/pubsub/docs/admin#managing_topics)'
'''

EXAMPLES = '''
- name: create a topic
  gcp_pubsub_topic:
    name: test-topic1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
'''

RETURN = '''
name:
  description:
  - Name of the topic.
  returned: success
  type: str
labels:
  description:
  - A set of key/value label pairs to assign to this Topic.
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
            state=dict(default='present', choices=['present', 'absent'], type='str'), name=dict(required=True, type='str'), labels=dict(type='dict')
        )
    )

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/pubsub']

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
            fetch = create(module, self_link(module))
            changed = True
        else:
            fetch = {}

    fetch.update({'changed': changed})

    module.exit_json(**fetch)


def create(module, link):
    auth = GcpSession(module, 'pubsub')
    return return_if_object(module, auth.put(link, resource_to_request(module)))


def update(module, link):
    module.fail_json(msg="Topic cannot be edited")


def delete(module, link):
    auth = GcpSession(module, 'pubsub')
    return return_if_object(module, auth.delete(link))


def resource_to_request(module):
    request = {u'name': module.params.get('name'), u'labels': module.params.get('labels')}
    request = encode_request(request, module)
    return_vals = {}
    for k, v in request.items():
        if v or v is False:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link, allow_not_found=True):
    auth = GcpSession(module, 'pubsub')
    return return_if_object(module, auth.get(link), allow_not_found)


def self_link(module):
    return "https://pubsub.googleapis.com/v1/projects/{project}/topics/{name}".format(**module.params)


def collection(module):
    return "https://pubsub.googleapis.com/v1/projects/{project}/topics".format(**module.params)


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
    except getattr(json.decoder, 'JSONDecodeError', ValueError):
        module.fail_json(msg="Invalid JSON response with error: %s" % response.text)

    result = decode_request(result, module)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def is_different(module, response):
    request = resource_to_request(module)
    response = response_to_hash(module, response)
    request = decode_request(request, module)

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
    return {u'name': response.get(u'name'), u'labels': response.get(u'labels')}


def decode_request(response, module):
    if 'name' in response:
        response['name'] = response['name'].split('/')[-1]
    return response


def encode_request(request, module):
    request['name'] = '/'.join(['projects', module.params['project'], 'topics', module.params['name']])
    return request


if __name__ == '__main__':
    main()
