#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: digital_ocean_droplet
short_description: Create and delete a DigitalOcean droplet
description:
     - Create, rebuild, or delete a droplet in DigitalOcean and optionally wait for it to be active.
version_added: "2.8"
author: "Gurchet Rai (@gurch101)"
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
  id:
    description:
     - Numeric, the droplet id you want to operate on.
    aliases: ['droplet_id']
  name:
    description:
     - Droplet name - must be a valid hostname or a FQDN. Required when I(state=present) and there's no such Droplet yet.
  unique_name:
    description:
     - deprecated and ignored parameter, consider it always True.
  size:
    description: >
      Droplet configuration slug, e.g. C(s-1vcpu-1gb), C(2gb), C(c-32vcpu-64gb), or C(s-32vcpu-192gb). If you forget to supply that,
      the module will build the smallest and the cheapest droplet C(s-1vcpu-1gb). If you need to grow your droplet you may do that later.
    aliases: ['size_id']
  image:
    description:
     - Image slug for new or rebuilt droplet. Required when I(state=present).
    aliases: ['image_id']
  region:
    description: >
      Datacenter slug you would like your droplet to be created in, e.g. C(sfo2), C(ams3), or C(sgp1). Required when I(state=present) and this is a new Droplet.
      New DO users please note: due to limited capacity, NYC2, AMS2, and SFO1 are currently unavailable for those who don't have resources already there.
    aliases: ['region_id']
  ssh_keys:
    description:
     - list of SSH key numeric IDs or fingerprints to put in ~root/authorized_keys on creation.
  private_networking:
    description:
     - add an additional, private network interface to droplet for intra-region communication.
    default: False
    type: bool
  user_data:
    description:
      - string data >64KB, e.g. a 'cloud-config' file or a Bash script to configure the Droplet on first boot.
    required: False
  ipv6:
    description:
      - enable IPv6 for new droplet.
    default: False
    type: bool
  wait:
    description:
     - Wait for the droplet to be active before returning.
    default: True
    type: bool
  wait_timeout:
    description:
     - How long before wait gives up, in seconds, when creating a droplet.
    default: 120
  backups:
    description:
     - indicates whether automated backups should be enabled.
    default: False
    type: bool
  monitoring:
    description:
     - indicates whether to install the DigitalOcean agent for monitoring.
    default: False
    type: bool
  tags:
    description:
     - List, A list of tag names as strings to apply to the Droplet after it is created. A tag can be existing or new.
  volumes:
    description:
     - List, A list including the unique string identifier for each Block Storage volume to be attached to the Droplet.
    required: False
  oauth_token:
    description:
     - DigitalOcean OAuth token. Can be specified in C(DO_API_KEY), C(DO_API_TOKEN), or C(DO_OAUTH_TOKEN) environment variables
    aliases: ['API_TOKEN']
    required: True
  rebuild:
    description:
     - force Droplet rebuild. You may supply image if you want it changed or omit it and just re-fresh your Droplet.
    default: False
    type: bool
requirements:
  - "python >= 2.6"
'''


EXAMPLES = '''
- name: create new or find existing droplet
  digital_ocean_droplet:
    state: present
    name: mydroplet.example.com
    oauth_token: "{{ lookup('file', '~/.do/api-key1') }}"
    size: 1gb
    region: sfo1
    image: ubuntu-16-04-x64
    tags: [ 'foo', 'bar' ]
    wait_timeout: 500
  register: my_droplet

- debug:
    msg: "ID is {{ my_droplet.data.droplet.id }}, IP is {{ my_droplet.data.ip_address }}"

- name: Check droplet exists, get details
  digital_ocean_droplet:
    name: mydroplet.example.com
    oauth_token: "{{ lookup('file', '~/.do/api-key1') }}"
  register: my_droplet

- name: ensure a droplet is like new
  digital_ocean_droplet:
    name: mydroplet.example.com
    oauth_token: "{{ lookup('file', '~/.do/api-key1') }}"
    rebuild: yes
    image: debian-9-x64  # may be omitted.
    wait_timeout: 240
  register: my_droplet
'''


RETURN = '''
# Digital Ocean API info https://developers.digitalocean.com/documentation/v2/#droplets
data:
    description: a DigitalOcean Droplet
    returned: changed
    type: dict
    sample: {
        "ip_address": "104.248.118.172",
        "ipv6_address": "2604:a880:400:d1::90a:6001",
        "private_ipv4_address": "10.136.122.141",
        "droplet": {
            "id": 3164494,
            "name": "mydroplet.example.com",
            "memory": 1024,
            "vcpus": 1,
            "disk": 25,
            "locked": false,
            "status": "active",
            "kernel": null,
            "created_at": "2014-11-14T16:36:31Z",
            "features": ["private_networking", "ipv6"],
            "backup_ids": [],
            "snapshot_ids": [],
            "image": {"slug": "debian-9-x64", ...},
            "volume_ids": [],
            "size": {"transfer": 1.0, "price_monthly": 5.0, "price_hourly": 0.00744, ...},
            "size_slug": "1gb",
            "networks": {"v4": [{"type": "public", ...}, {"type": "private", ...},], "v6": [{"type": "public", ...}]},
            "region": {"slug":"sfo1",...},
            "tags": []
        }
    }
'''

import time
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.digital_ocean import DigitalOceanHelper


class DODroplet(object):
    def __init__(self, module):
        self.module = module
        self._id = self.module.params['id']
        self._name = self.module.params['name']
        self._droplet = None  # == _id if found by _id
        self.rest = DigitalOceanHelper(module)
        # pop all the parameters which we never POST as data
        self.rebuild = self.module.params.pop('rebuild')
        self.wait = self.module.params.pop('wait', True)
        self.wait_timeout = self.module.params.pop('wait_timeout', 120)
        self.module.params.pop('oauth_token')
        if self.module.params.pop('unique_name', None) is not None:
            self.module.warn("Parameter `unique_name` is deprecated. Consider it's always True.")
        if self._id and self._name:
            self.module.warn("Both id {0} and name {1} supplied. Your play may turn unexpectedly!".
                             format(self._id, self._name))

    def get_by_id(self, droplet_id):
        if not droplet_id:
            return None
        response = self.rest.get('droplets/{0}'.format(droplet_id))
        if response.status_code == 200:
            self._droplet = droplet_id
            return response.json
        return None

    def find_by_name(self, droplet_name):
        if not droplet_name:
            return None
        page = 1
        while page is not None:
            response = self.rest.get('droplets?page={0}'.format(page))
            json_data = response.json
            if response.status_code == 200:
                for droplet in json_data['droplets']:
                    if droplet['name'] == droplet_name:
                        self._droplet = droplet_name
                        return {'droplet': droplet}
                if 'links' in json_data and 'pages' in json_data['links'] and 'next' in json_data['links']['pages']:
                    page += 1
                else:
                    page = None
        return None

    def expose_addresses(self, data):
        """
         Expose IP addresses as their own property allowing users extend to additional tasks
        """
        _data = data
        for k, v in data.items():
            setattr(self, k, v)
        networks = _data['droplet']['networks']
        for network in networks.get('v4', []):
            if network['type'] == 'public':
                _data['ip_address'] = network['ip_address']
            else:
                _data['private_ipv4_address'] = network['ip_address']
        for network in networks.get('v6', []):
            if network['type'] == 'public':
                _data['ipv6_address'] = network['ip_address']
            else:
                _data['private_ipv6_address'] = network['ip_address']
        return _data

    def find_droplet(self):
        json_data = self.get_by_id(self._id)
        if not json_data:
            json_data = self.find_by_name(self._name)
        return json_data

    def _params_ok(self, name, image, region):
        """
        When creating droplet we need at least name, image, and region.
        :return:
        True if all the parameters were supplied.
        """
        return name and image and region

    def get(self):
        """
        Find the droplet (either by id or name), rebuild if requested so, build if not found.
        """
        json_data = self.find_droplet()
        _size = self.module.params['size']
        _image = self.module.params['image']
        _region = self.module.params['region']
        if json_data and not self.rebuild:
            self.module.exit_json(changed=False, data=self.expose_addresses(json_data))
        elif self.rebuild and not json_data:
            self.module.fail_json(changed=False, msg='droplet {0} not found. Rebuild failed.'.format(self._droplet))
        elif self.rebuild and json_data:
            self._rebuild(json_data)  # _rebuild() should not return here.
        # we are going to build a new droplet now. Final checks.
        if self._id:
            self.module.warn("Trying to build {0}. Parameter id is found, it makes no sense here!".format(self._name))
        if not _size:
            _default_size = 's-1vcpu-1gb'
            self.module.warn("Missing 'size' parameter. Using size={0}".format(_default_size))
            _size = _default_size
        if not self._params_ok(self._name, _image, _region):
            self.module.fail_json(changed=False, msg='Droplet not created. Not enough parameters: name={0} region={1}'
                                                     ' image={2} size={3}'.format(self._name, _region, _image, _size))
        if self.module.check_mode:
            self.module.exit_json(changed=True)
        response = self.rest.post('droplets', data=self.module.params)
        if response.status_code >= 400:
            self.module.fail_json(changed=False, msg=response.json['message'])
        if self.wait:
            self.ensure_active(response.json['droplet']['id'])
        self.module.exit_json(
            changed=True, data=self.expose_addresses(response.json))

    def _rebuild(self, json_data):
        if self._id and self._name:
            self.module.warn("Trying to rebuild droplet id={0}. Parameter name is found too, it makes no sense here!".format(self._id))
        if self.module.check_mode:
            self.module.exit_json(changed=True)
        droplet_id = json_data['droplet']['id']
        curr_image = json_data['droplet']['image']['id']
        do_image = self.module.params['image'] if 'image' in self.module.params and self.module.params['image'] \
            else curr_image
        cmd_data = {'type': "rebuild", 'image': do_image}
        response = self.rest.post('droplets/{0}/actions'.format(droplet_id), data=cmd_data)
        if response.status_code >= 400:
            self.module.fail_json(changed=False, msg=response.json['message'])
        self.module.exit_json(  # wait for rebuild to finish, enrich received JSON, then return it.
            changed=True, data=self.expose_addresses(
                self.ensure_unlocked(droplet_id)))

    def delete(self):
        json_data = self.find_droplet()
        if json_data:
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            response = self.rest.delete('droplets/{0}'.format(json_data['droplet']['id']))
            if response.status_code == 204:
                self.module.exit_json(changed=True, msg='Droplet deleted')
            self.module.fail_json(changed=False, msg='Failed to delete droplet {0}'.format(self._droplet))
        else:
            self.module.exit_json(changed=False, msg='Droplet {0} not found'.format(self._droplet))

    def ensure_unlocked(self, droplet_id):
        end_time = time.time() + self.wait_timeout
        while time.time() < end_time:
            response = self.rest.get('droplets/{0}'.format(droplet_id))
            if not response.json['droplet']['locked']:
                return response.json
            time.sleep(min(2, end_time - time.time()))
        self.module.fail_json(msg='Droplet action finish timeout')

    def ensure_active(self, droplet_id):
        end_time = time.time() + self.wait_timeout
        while time.time() < end_time:
            response = self.rest.get('droplets/{0}'.format(droplet_id))
            if response.json['droplet']['status'] == 'active':
                return response.json
            time.sleep(min(2, end_time - time.time()))
        self.module.fail_json(msg='Wait for droplet status=active timeout')


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(choices=['present', 'absent'], default='present'),
            oauth_token=dict(
                aliases=['API_TOKEN'],
                no_log=True,
                fallback=(env_fallback, ['DO_API_TOKEN', 'DO_API_KEY', 'DO_OAUTH_TOKEN'])
            ),
            name=dict(type='str'),
            size=dict(aliases=['size_id']),
            image=dict(aliases=['image_id']),
            rebuild=dict(type='bool', default=False),
            region=dict(aliases=['region_id']),
            ssh_keys=dict(type='list'),
            private_networking=dict(type='bool', default=False),
            backups=dict(type='bool', default=False),
            monitoring=dict(type='bool', default=False),
            id=dict(aliases=['droplet_id'], type='int'),
            user_data=dict(default=None),
            ipv6=dict(type='bool', default=False),
            volumes=dict(type='list'),
            tags=dict(type='list'),
            wait=dict(type='bool', default=True),
            wait_timeout=dict(default=120, type='int'),
            unique_name=dict(),
        ),
        required_one_of=(
            ['id', 'name'],
        ),
        supports_check_mode=True,
    )
    state = module.params.pop('state')
    droplet = DODroplet(module)
    if state == 'present':
        droplet.get()
    elif state == 'absent':
        droplet.delete()


if __name__ == '__main__':
    main()
