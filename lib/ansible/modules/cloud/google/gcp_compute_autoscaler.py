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
module: gcp_compute_autoscaler
description:
- Represents an Autoscaler resource.
- Autoscalers allow you to automatically scale virtual machine instances in managed
  instance groups according to an autoscaling policy that you define.
short_description: Creates a GCP Autoscaler
version_added: '2.9'
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
    type: str
  name:
    description:
    - Name of the resource. The name must be 1-63 characters long and match the regular
      expression `[a-z]([-a-z0-9]*[a-z0-9])?` which means the first character must
      be a lowercase letter, and all following characters must be a dash, lowercase
      letter, or digit, except the last character, which cannot be a dash.
    required: true
    type: str
  description:
    description:
    - An optional description of this resource.
    required: false
    type: str
  autoscaling_policy:
    description:
    - 'The configuration parameters for the autoscaling algorithm. You can define
      one or more of the policies for an autoscaler: cpuUtilization, customMetricUtilizations,
      and loadBalancingUtilization.'
    - If none of these are specified, the default will be to autoscale based on cpuUtilization
      to 0.6 or 60%.
    required: true
    type: dict
    suboptions:
      min_num_replicas:
        description:
        - The minimum number of replicas that the autoscaler can scale down to. This
          cannot be less than 0. If not provided, autoscaler will choose a default
          value depending on maximum number of instances allowed.
        required: false
        type: int
        aliases:
        - minReplicas
      max_num_replicas:
        description:
        - The maximum number of instances that the autoscaler can scale up to. This
          is required when creating or updating an autoscaler. The maximum number
          of replicas should not be lower than minimal number of replicas.
        required: true
        type: int
        aliases:
        - maxReplicas
      cool_down_period_sec:
        description:
        - The number of seconds that the autoscaler should wait before it starts collecting
          information from a new instance. This prevents the autoscaler from collecting
          information when the instance is initializing, during which the collected
          usage would not be reliable. The default time autoscaler waits is 60 seconds.
        - Virtual machine initialization times might vary because of numerous factors.
          We recommend that you test how long an instance may take to initialize.
          To do this, create an instance and time the startup process.
        required: false
        default: '60'
        type: int
        aliases:
        - cooldownPeriod
      cpu_utilization:
        description:
        - Defines the CPU utilization policy that allows the autoscaler to scale based
          on the average CPU utilization of a managed instance group.
        required: false
        type: dict
        suboptions:
          utilization_target:
            description:
            - The target CPU utilization that the autoscaler should maintain.
            - Must be a float value in the range (0, 1]. If not specified, the default
              is 0.6.
            - If the CPU level is below the target utilization, the autoscaler scales
              down the number of instances until it reaches the minimum number of
              instances you specified or until the average CPU of your instances reaches
              the target utilization.
            - If the average CPU is above the target utilization, the autoscaler scales
              up until it reaches the maximum number of instances you specified or
              until the average utilization reaches the target utilization.
            required: false
            type: str
            aliases:
            - target
      custom_metric_utilizations:
        description:
        - Defines the CPU utilization policy that allows the autoscaler to scale based
          on the average CPU utilization of a managed instance group.
        required: false
        type: list
        aliases:
        - metric
        suboptions:
          metric:
            description:
            - The identifier (type) of the Stackdriver Monitoring metric.
            - The metric cannot have negative values.
            - The metric must have a value type of INT64 or DOUBLE.
            required: true
            type: str
            aliases:
            - name
          utilization_target:
            description:
            - The target value of the metric that autoscaler should maintain. This
              must be a positive value. A utilization metric scales number of virtual
              machines handling requests to increase or decrease proportionally to
              the metric.
            - For example, a good metric to use as a utilizationTarget is U(www.googleapis.com/compute/instance/network/received_bytes_count).
            - The autoscaler will work to keep this value constant for each of the
              instances.
            required: false
            type: str
            aliases:
            - target
          utilization_target_type:
            description:
            - Defines how target utilization value is expressed for a Stackdriver
              Monitoring metric. Either GAUGE, DELTA_PER_SECOND, or DELTA_PER_MINUTE.
            - 'Some valid choices include: "GAUGE", "DELTA_PER_SECOND", "DELTA_PER_MINUTE"'
            required: false
            type: str
            aliases:
            - type
      load_balancing_utilization:
        description:
        - Configuration parameters of autoscaling based on a load balancer.
        required: false
        type: dict
        suboptions:
          utilization_target:
            description:
            - Fraction of backend capacity utilization (set in HTTP(s) load balancing
              configuration) that autoscaler should maintain. Must be a positive float
              value. If not defined, the default is 0.8.
            required: false
            type: str
            aliases:
            - target
  target:
    description:
    - URL of the managed instance group that this autoscaler will scale.
    - 'This field represents a link to a InstanceGroupManager resource in GCP. It
      can be specified in two ways. First, you can place a dictionary with key ''selfLink''
      and value of your resource''s selfLink Alternatively, you can add `register:
      name-of-resource` to a gcp_compute_instance_group_manager task and then set
      this target field to "{{ name-of-resource }}"'
    required: true
    type: dict
  zone:
    description:
    - URL of the zone where the instance group resides.
    required: true
    type: str
  project:
    description:
    - The Google Cloud Platform project to use.
    type: str
  auth_kind:
    description:
    - The type of credential used.
    type: str
    required: true
    choices:
    - application
    - machineaccount
    - serviceaccount
  service_account_contents:
    description:
    - The contents of a Service Account JSON file, either in a dictionary or as a
      JSON string that represents it.
    type: jsonarg
  service_account_file:
    description:
    - The path of a Service Account JSON file if serviceaccount is selected as type.
    type: path
  service_account_email:
    description:
    - An optional service account email address if machineaccount is selected and
      the user does not wish to use the default email.
    type: str
  scopes:
    description:
    - Array of scopes to be used
    type: list
  env_type:
    description:
    - Specifies which Ansible environment you're running this module within.
    - This should not be set unless you know what you're doing.
    - This only alters the User Agent string for any API requests.
    type: str
notes:
- 'API Reference: U(https://cloud.google.com/compute/docs/reference/rest/v1/autoscalers)'
- 'Autoscaling Groups of Instances: U(https://cloud.google.com/compute/docs/autoscaler/)'
- for authentication, you can set service_account_file using the C(gcp_service_account_file)
  env variable.
- for authentication, you can set service_account_contents using the C(GCP_SERVICE_ACCOUNT_CONTENTS)
  env variable.
- For authentication, you can set service_account_email using the C(GCP_SERVICE_ACCOUNT_EMAIL)
  env variable.
- For authentication, you can set auth_kind using the C(GCP_AUTH_KIND) env variable.
- For authentication, you can set scopes using the C(GCP_SCOPES) env variable.
- Environment variables values will only be used if the playbook values are not set.
- The I(service_account_email) and I(service_account_file) options are mutually exclusive.
'''

EXAMPLES = '''
- name: create a network
  gcp_compute_network:
    name: network-instancetemplate
    project: "{{ gcp_project }}"
    auth_kind: "{{ gcp_cred_kind }}"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
  register: network

- name: create a address
  gcp_compute_address:
    name: address-instancetemplate
    region: us-central1
    project: "{{ gcp_project }}"
    auth_kind: "{{ gcp_cred_kind }}"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
  register: address

- name: create a instance template
  gcp_compute_instance_template:
    name: "{{ resource_name }}"
    properties:
      disks:
      - auto_delete: 'true'
        boot: 'true'
        initialize_params:
          source_image: projects/ubuntu-os-cloud/global/images/family/ubuntu-1604-lts
      machine_type: n1-standard-1
      network_interfaces:
      - network: "{{ network }}"
        access_configs:
        - name: test-config
          type: ONE_TO_ONE_NAT
          nat_ip: "{{ address }}"
    project: "{{ gcp_project }}"
    auth_kind: "{{ gcp_cred_kind }}"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
  register: instancetemplate

- name: create a instance group manager
  gcp_compute_instance_group_manager:
    name: "{{ resource_name }}"
    base_instance_name: test1-child
    instance_template: "{{ instancetemplate }}"
    target_size: 3
    zone: us-central1-a
    project: "{{ gcp_project }}"
    auth_kind: "{{ gcp_cred_kind }}"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
  register: igm

- name: create a autoscaler
  gcp_compute_autoscaler:
    name: test_object
    zone: us-central1-a
    target: "{{ igm }}"
    autoscaling_policy:
      max_num_replicas: 5
      min_num_replicas: 1
      cool_down_period_sec: 60
      cpu_utilization:
        utilization_target: 0.5
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
'''

RETURN = '''
id:
  description:
  - Unique identifier for the resource.
  returned: success
  type: int
creationTimestamp:
  description:
  - Creation timestamp in RFC3339 text format.
  returned: success
  type: str
name:
  description:
  - Name of the resource. The name must be 1-63 characters long and match the regular
    expression `[a-z]([-a-z0-9]*[a-z0-9])?` which means the first character must be
    a lowercase letter, and all following characters must be a dash, lowercase letter,
    or digit, except the last character, which cannot be a dash.
  returned: success
  type: str
description:
  description:
  - An optional description of this resource.
  returned: success
  type: str
autoscalingPolicy:
  description:
  - 'The configuration parameters for the autoscaling algorithm. You can define one
    or more of the policies for an autoscaler: cpuUtilization, customMetricUtilizations,
    and loadBalancingUtilization.'
  - If none of these are specified, the default will be to autoscale based on cpuUtilization
    to 0.6 or 60%.
  returned: success
  type: complex
  contains:
    minNumReplicas:
      description:
      - The minimum number of replicas that the autoscaler can scale down to. This
        cannot be less than 0. If not provided, autoscaler will choose a default value
        depending on maximum number of instances allowed.
      returned: success
      type: int
    maxNumReplicas:
      description:
      - The maximum number of instances that the autoscaler can scale up to. This
        is required when creating or updating an autoscaler. The maximum number of
        replicas should not be lower than minimal number of replicas.
      returned: success
      type: int
    coolDownPeriodSec:
      description:
      - The number of seconds that the autoscaler should wait before it starts collecting
        information from a new instance. This prevents the autoscaler from collecting
        information when the instance is initializing, during which the collected
        usage would not be reliable. The default time autoscaler waits is 60 seconds.
      - Virtual machine initialization times might vary because of numerous factors.
        We recommend that you test how long an instance may take to initialize. To
        do this, create an instance and time the startup process.
      returned: success
      type: int
    cpuUtilization:
      description:
      - Defines the CPU utilization policy that allows the autoscaler to scale based
        on the average CPU utilization of a managed instance group.
      returned: success
      type: complex
      contains:
        utilizationTarget:
          description:
          - The target CPU utilization that the autoscaler should maintain.
          - Must be a float value in the range (0, 1]. If not specified, the default
            is 0.6.
          - If the CPU level is below the target utilization, the autoscaler scales
            down the number of instances until it reaches the minimum number of instances
            you specified or until the average CPU of your instances reaches the target
            utilization.
          - If the average CPU is above the target utilization, the autoscaler scales
            up until it reaches the maximum number of instances you specified or until
            the average utilization reaches the target utilization.
          returned: success
          type: str
    customMetricUtilizations:
      description:
      - Defines the CPU utilization policy that allows the autoscaler to scale based
        on the average CPU utilization of a managed instance group.
      returned: success
      type: complex
      contains:
        metric:
          description:
          - The identifier (type) of the Stackdriver Monitoring metric.
          - The metric cannot have negative values.
          - The metric must have a value type of INT64 or DOUBLE.
          returned: success
          type: str
        utilizationTarget:
          description:
          - The target value of the metric that autoscaler should maintain. This must
            be a positive value. A utilization metric scales number of virtual machines
            handling requests to increase or decrease proportionally to the metric.
          - For example, a good metric to use as a utilizationTarget is U(www.googleapis.com/compute/instance/network/received_bytes_count).
          - The autoscaler will work to keep this value constant for each of the instances.
          returned: success
          type: str
        utilizationTargetType:
          description:
          - Defines how target utilization value is expressed for a Stackdriver Monitoring
            metric. Either GAUGE, DELTA_PER_SECOND, or DELTA_PER_MINUTE.
          returned: success
          type: str
    loadBalancingUtilization:
      description:
      - Configuration parameters of autoscaling based on a load balancer.
      returned: success
      type: complex
      contains:
        utilizationTarget:
          description:
          - Fraction of backend capacity utilization (set in HTTP(s) load balancing
            configuration) that autoscaler should maintain. Must be a positive float
            value. If not defined, the default is 0.8.
          returned: success
          type: str
target:
  description:
  - URL of the managed instance group that this autoscaler will scale.
  returned: success
  type: dict
zone:
  description:
  - URL of the zone where the instance group resides.
  returned: success
  type: str
'''

################################################################################
# Imports
################################################################################

from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest, remove_nones_from_dict, replace_resource_dict
import json
import time

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            description=dict(type='str'),
            autoscaling_policy=dict(
                required=True,
                type='dict',
                options=dict(
                    min_num_replicas=dict(type='int', aliases=['minReplicas']),
                    max_num_replicas=dict(required=True, type='int', aliases=['maxReplicas']),
                    cool_down_period_sec=dict(default=60, type='int', aliases=['cooldownPeriod']),
                    cpu_utilization=dict(type='dict', options=dict(utilization_target=dict(type='str', aliases=['target']))),
                    custom_metric_utilizations=dict(
                        type='list',
                        elements='dict',
                        aliases=['metric'],
                        options=dict(
                            metric=dict(required=True, type='str', aliases=['name']),
                            utilization_target=dict(type='str', aliases=['target']),
                            utilization_target_type=dict(type='str', aliases=['type']),
                        ),
                    ),
                    load_balancing_utilization=dict(type='dict', options=dict(utilization_target=dict(type='str', aliases=['target']))),
                ),
            ),
            target=dict(required=True, type='dict'),
            zone=dict(required=True, type='str'),
        )
    )

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/compute']

    state = module.params['state']
    kind = 'compute#autoscaler'

    fetch = fetch_resource(module, self_link(module), kind)
    changed = False

    if fetch:
        if state == 'present':
            if is_different(module, fetch):
                update(module, self_link(module), kind)
                fetch = fetch_resource(module, self_link(module), kind)
                changed = True
        else:
            delete(module, self_link(module), kind)
            fetch = {}
            changed = True
    else:
        if state == 'present':
            fetch = create(module, collection(module), kind)
            changed = True
        else:
            fetch = {}

    fetch.update({'changed': changed})

    module.exit_json(**fetch)


def create(module, link, kind):
    auth = GcpSession(module, 'compute')
    return wait_for_operation(module, auth.post(link, resource_to_request(module)))


def update(module, link, kind):
    auth = GcpSession(module, 'compute')
    return wait_for_operation(module, auth.put(link, resource_to_request(module)))


def delete(module, link, kind):
    auth = GcpSession(module, 'compute')
    return wait_for_operation(module, auth.delete(link))


def resource_to_request(module):
    request = {
        u'kind': 'compute#autoscaler',
        u'zone': module.params.get('zone'),
        u'name': module.params.get('name'),
        u'description': module.params.get('description'),
        u'autoscalingPolicy': AutoscalerAutoscalingpolicy(module.params.get('autoscaling_policy', {}), module).to_request(),
        u'target': replace_resource_dict(module.params.get(u'target', {}), 'selfLink'),
    }
    return_vals = {}
    for k, v in request.items():
        if v or v is False:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link, kind, allow_not_found=True):
    auth = GcpSession(module, 'compute')
    return return_if_object(module, auth.get(link), kind, allow_not_found)


def self_link(module):
    return "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/autoscalers/{name}".format(**module.params)


def collection(module):
    return "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/autoscalers".format(**module.params)


def return_if_object(module, response, kind, allow_not_found=False):
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

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def is_different(module, response):
    request = resource_to_request(module)
    response = response_to_hash(module, response)

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
        u'id': response.get(u'id'),
        u'creationTimestamp': response.get(u'creationTimestamp'),
        u'name': module.params.get('name'),
        u'description': response.get(u'description'),
        u'autoscalingPolicy': AutoscalerAutoscalingpolicy(response.get(u'autoscalingPolicy', {}), module).from_response(),
        u'target': response.get(u'target'),
    }


def async_op_url(module, extra_data=None):
    if extra_data is None:
        extra_data = {}
    url = "https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/operations/{op_id}"
    combined = extra_data.copy()
    combined.update(module.params)
    return url.format(**combined)


def wait_for_operation(module, response):
    op_result = return_if_object(module, response, 'compute#operation')
    if op_result is None:
        return {}
    status = navigate_hash(op_result, ['status'])
    wait_done = wait_for_completion(status, op_result, module)
    return fetch_resource(module, navigate_hash(wait_done, ['targetLink']), 'compute#autoscaler')


def wait_for_completion(status, op_result, module):
    op_id = navigate_hash(op_result, ['name'])
    op_uri = async_op_url(module, {'op_id': op_id})
    while status != 'DONE':
        raise_if_errors(op_result, ['error', 'errors'], module)
        time.sleep(1.0)
        op_result = fetch_resource(module, op_uri, 'compute#operation', False)
        status = navigate_hash(op_result, ['status'])
    return op_result


def raise_if_errors(response, err_path, module):
    errors = navigate_hash(response, err_path)
    if errors is not None:
        module.fail_json(msg=errors)


class AutoscalerAutoscalingpolicy(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict(
            {
                u'minNumReplicas': self.request.get('min_num_replicas'),
                u'maxNumReplicas': self.request.get('max_num_replicas'),
                u'coolDownPeriodSec': self.request.get('cool_down_period_sec'),
                u'cpuUtilization': AutoscalerCpuutilization(self.request.get('cpu_utilization', {}), self.module).to_request(),
                u'customMetricUtilizations': AutoscalerCustommetricutilizationsArray(
                    self.request.get('custom_metric_utilizations', []), self.module
                ).to_request(),
                u'loadBalancingUtilization': AutoscalerLoadbalancingutilization(self.request.get('load_balancing_utilization', {}), self.module).to_request(),
            }
        )

    def from_response(self):
        return remove_nones_from_dict(
            {
                u'minNumReplicas': self.request.get(u'minNumReplicas'),
                u'maxNumReplicas': self.request.get(u'maxNumReplicas'),
                u'coolDownPeriodSec': self.request.get(u'coolDownPeriodSec'),
                u'cpuUtilization': AutoscalerCpuutilization(self.request.get(u'cpuUtilization', {}), self.module).from_response(),
                u'customMetricUtilizations': AutoscalerCustommetricutilizationsArray(
                    self.request.get(u'customMetricUtilizations', []), self.module
                ).from_response(),
                u'loadBalancingUtilization': AutoscalerLoadbalancingutilization(self.request.get(u'loadBalancingUtilization', {}), self.module).from_response(),
            }
        )


class AutoscalerCpuutilization(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({u'utilizationTarget': self.request.get('utilization_target')})

    def from_response(self):
        return remove_nones_from_dict({u'utilizationTarget': self.request.get(u'utilizationTarget')})


class AutoscalerCustommetricutilizationsArray(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = []

    def to_request(self):
        items = []
        for item in self.request:
            items.append(self._request_for_item(item))
        return items

    def from_response(self):
        items = []
        for item in self.request:
            items.append(self._response_from_item(item))
        return items

    def _request_for_item(self, item):
        return remove_nones_from_dict(
            {u'metric': item.get('metric'), u'utilizationTarget': item.get('utilization_target'), u'utilizationTargetType': item.get('utilization_target_type')}
        )

    def _response_from_item(self, item):
        return remove_nones_from_dict(
            {u'metric': item.get(u'metric'), u'utilizationTarget': item.get(u'utilizationTarget'), u'utilizationTargetType': item.get(u'utilizationTargetType')}
        )


class AutoscalerLoadbalancingutilization(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({u'utilizationTarget': self.request.get('utilization_target')})

    def from_response(self):
        return remove_nones_from_dict({u'utilizationTarget': self.request.get(u'utilizationTarget')})


if __name__ == '__main__':
    main()
