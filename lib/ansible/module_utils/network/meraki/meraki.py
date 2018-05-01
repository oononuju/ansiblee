# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component

# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.

# Copyright: (c) 2018, Kevin Breit <kevin.breit@kevinbreit.net>
# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
from ansible.module_utils.basic import AnsibleModule, json, env_fallback
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_native, to_bytes, to_text


def meraki_argument_spec():
    return dict(auth_key=dict(type='str', no_log=True, fallback=(env_fallback, ['MERAKI_KEY'])),
                host=dict(type='str', default='api.meraki.com'),
                use_proxy=dict(type='bool', default=False),
                use_https=dict(type='bool', default=True),
                validate_certs=dict(type='bool', default=True),
                output_level=dict(type='str', default='normal', choices=['normal', 'debug']),
                timeout=dict(type='int', default=30),
                org_name=dict(type='str', aliases=['organization']),
                org_id=dict(type='str'),
                )


class MerakiModule(object):

    def __init__(self, module, function=None):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = dict()
        self.function = function

        # error output
        self.error = dict(code=None, text=None)

        # normal output
        self.existing = None

        # info output
        self.config = dict()
        self.original = None
        self.proposed = dict()
        self.merged = None

        # debug output
        self.filter_string = ''
        self.method = None
        self.path = None
        self.response = None
        self.status = None
        self.url = None

        '''
        If URLs need to be modified or added for specific purposes, use .update() on the url_catalog dictionary
        '''
        self.get_urls = {'organizations': '/organizations',
                         'networks': '/organizations/{org_id}/networks',
                         'admins': '/organizations/{org_id}/admins',
                         'configTemplates': '/organizations/{org_id}/configTemplates',
                         'samlRoles': '/organizations/{org_id}/samlRoles',
                         'ssids': '/networks/{net_id}/ssids',
                         'groupPolicies': '/networks/{net_id}/groupPolicies',
                         'staticRoutes': '/networks/{net_id}/staticRoutes',
                         'vlans': '/networks/{net_id}/vlans',
                         'devices': '/networks/{net_id}/devices',
                         }

        self.get_one_urls = {'organizations': '/organizations/{org_id}',
                             'networks': '/networks/{net_id}',
                             }

        # Module should add URLs which are required by the module
        self.url_catalog = {'get_all': self.get_urls,
                            'get_one': self.get_one_urls,
                            'create': None,
                            'update': None,
                            'delete': None,
                            'misc': None,
                            }

        if self.module._debug or self.params['output_level'] == 'debug':
            self.module.warn('Enable debug output because ANSIBLE_DEBUG was set or output_level is set to debug.')

        # TODO: This needs to be tested
        self.module.required_if = [('state', 'present', ['org_name']),
                                   ('state', 'absent', ['org_name']),
                                   ]
        # self.module.mutually_exclusive = [('org_id', 'org_name'),
        #                                   ]
        self.modifiable_methods = ['POST', 'PUT', 'DELETE']

        if self.params['auth_key'] is None:
            try:
                self.params['auth_key'] = os.environ['MERAKI_KEY']
            except KeyError:
                self.fail_json(msg='Meraki Dashboard API key not set')

        self.headers = {'Content-Type': 'application/json',
                        'X-Cisco-Meraki-API-Key': module.params['auth_key'],
                        }


    def define_protocol(self):
        ''' Set protocol based on use_https parameters '''
        if self.params['use_https'] is True:
            self.params['protocol'] = 'https'
        else:
            self.params['protocol'] = 'http'

    def is_update_required(self, original, proposed):
        ''' Compare original and proposed data to see if an update is needed '''
        is_changed = False
        ignored_keys = ('id', 'organizationId')

        # self.fail_json(msg="Update required check", original=original, proposed=proposed)

        for k, v in original.items():
            try:
                if k not in ignored_keys:
                    if v != proposed[k]:
                        is_changed = True
            except KeyError:
                if v != '':
                    is_changed = True
        for k, v in proposed.items():
            try:
                if k not in ignored_keys:
                    if v != original[k]:
                        is_changed = True
            except KeyError:
                if v != '':
                    is_changed = True
        return is_changed

    def get_orgs(self):
        ''' Downloads all organizations '''
        return json.loads(self.request('/organizations', method='GET'))

    def is_org_valid(self, data, org_name=None, org_id=None):
        ''' Checks whether a specific org exists and is duplicated '''
        ''' If 0, doesn't exist. 1, exists and not duplicated. >1 duplicated '''
        org_count = 0
        if org_name is not None:
            for o in data:
                if o['name'] == org_name:
                    org_count += 1
        if org_id is not None:
            for o in data:
                if o['id'] == org_id:
                    org_count += 1
        return org_count

    def get_org_id(self, org_name):
        ''' Returns an organization id based on organization name, only if unique
            If org_id is specified as parameter, return that instead of a lookup
        '''
        orgs = self.get_orgs()
        if self.params['org_id'] is not None:
            if self.is_org_valid(orgs, org_id=self.params['org_id']) is True:
                return self.params['org_id']
        org_count = self.is_org_valid(orgs, org_name=org_name)
        if org_count == 0:
            self.fail_json(msg='There are no organizations with the name {org_name}'.format(org_name=org_name))
        if org_count > 1:
            self.fail_json(msg='There are multiple organizations with the name {org_name}'.format(org_name=org_name))
        elif org_count == 1:
            for i in orgs:
                if org_name == i['name']:
                    # self.fail_json(msg=i['id'])
                    return str(i['id'])

    def get_net(self, org_name, net_name, data=None):
        ''' Return network information '''
        if not data:
            org_id = self.get_org_id(org_name)
            path = '/organizations/{org_id}/networks/{net_id}'.format(org_id=org_id, net_id=self.get_net_id(org_name=org_name, net_name=net_name, data=data))
            return json.loads(self.request('GET', path))
        else:
            for n in data:
                if n['name'] == net_name:
                    return n

    def get_net_id(self, org_name=None, net_name=None, data=None):
        ''' Return network id from lookup or existing data '''
        if not data:
            self.fail_json(msg='Must implement lookup')
        for n in data:
            if n['name'] == net_name:
                return n['id']
        self.fail_json(msg='No network found with the name {0}'.format(net_name))

    def construct_path(self, action, function=None, org_id=None, net_id=None, org_name=None, append=None):
        built_path = None
        if function is None:
            built_path = self.url_catalog[action][self.function]
        else:
            self.function = function
            built_path = self.url_catalog[action][function]

        if org_name:
            org_id = self.get_org_id(org_name)

        org_only = {'org_id': org_id,
                    }
        net_only = {'net_id': net_id,
                    }
        org_net = {'org_id': org_id,
                   'net_id': net_id,
                   }
        built_path = self.url_catalog[action][self.function]

        if org_id and net_id:
            built_path = built_path.format(**org_net)
        elif org_id and not net_id:
            built_path = built_path.format(**org_only)
        elif not org_id and net_id:
            built_path = built_path.format(**net_only)
        # self.fail_json(msg=built_path)
        return built_path

    # def construct_path(self, action, function=None, org_id=None, net_id=None, org_name=None, append=None):
    #     org_only = {'org_id': org_id,
    #                 }
    #     net_only = {'net_id': net_id,
    #                 }
    #     org_net = {'org_id': org_id,
    #                 'net_id': net_id,
    #                 }

    #     built_path = None
    #     if function is None:
    #         built_path = self.url_catalog[action][self.function]
    #     else:
    #         self.function = function
    #         built_path = self.url_catalog[action][function]
    #     if 'org_id' in built_path:  # TODO: This is a mess, fix it
    #         if org_id is None:
    #             built_path = built_path.format(org_id=self.get_org_id(org_name))
    #         else:
    #             built_path = built_path.format(org_id=str(org_id), net_id=None)
    #     if 'net_id' in built_path:
    #         if net_id is None:
    #             built_path = built_path.format(net_id=self.get_net_id(self.module.params['net_name']))
    #         else:
    #             built_path = built_path.format(net_id=net_id)
    #     return built_path

    def request(self, path, method=None, payload=None):
        ''' Generic HTTP method for Meraki requests '''
        self.path = path
        self.define_protocol()
        # if self.define_method() is -1:  # No changes are needed to existing object
        #     return

        if method is not None:
            self.method = method
        self.url = '{0}://{1}/api/v0/{2}'.format(self.params['protocol'], self.params['host'], self.path.lstrip('/'))
        resp, info = fetch_url(self.module, self.url,
                               headers=self.headers,
                               data=payload,
                               method=self.method,
                               timeout=self.params['timeout'],
                               use_proxy=self.params['use_proxy'],
                               )
        self.response = info['msg']
        self.status = info['status']

        try:
            if self.status >= 400:
                # self.error['text'] = json.loads(info['body'])
                # self.error['code'] = info['status']
                self.fail_json(msg='Dashboard API error %(code)s: %(text)s' % self.error)
            elif self.status >= 300:
                # self.error['text'] = json.loads(info['body'])
                # self.error['code'] = info['status']
                self.fail_json(msg='Dashboard API error %(code)s: %(text)s' % self.error)
        except KeyError:
            self.fail_json(msg='Connection failed for %(url)s. %(msg)s' % info)
        # if self.status >= 201 and self.status <= 299 and method == 'POST':
        #     self.result['changed'] = True
        # if self.status == 200 and method == 'PUT':
        #     self.result['changed'] = True
        return to_native(resp.read())

    def exit_json(self, **kwargs):
        if 'state' in self.params:
            if self.params['state'] in ('absent', 'present'):
                if self.params['output_level'] in ('debug', 'info'):
                    self.result['previous'] = self.existing
        self.result['response'] = self.response
        self.result['status'] = self.status
        # Return the gory details when we need it
        if self.params['output_level'] == 'debug':
            if 'state' in self.params:
                self.result['filter_string'] = self.filter_string
            self.result['method'] = self.method
            # self.result['path'] = self.path  # Adding 'path' in result causes state: absent in output

            self.result['url'] = self.url

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        # Return error information, if we have it
        self.result['error'] = self.error

        if 'state' in self.params:
            if self.params['state'] in ('absent', 'present'):
                if self.params['output_level'] in ('debug', 'info'):
                    self.result['previous'] = self.existing
        self.result['response'] = self.response
        self.result['status'] = self.status

        if self.params['output_level'] == 'debug':
            if self.url is not None:
                if 'state' in self.params:
                    self.result['filter_string'] = self.filter_string
                self.result['method'] = self.method
                # self.result['path'] = self.path  # Adding 'path' in result causes state: absent in output
                self.result['url'] = self.url

        if 'state' in self.params:
            if self.params['output_level'] in ('debug', 'info'):
                self.result['sent'] = self.config
                self.result['proposed'] = self.proposed

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)
