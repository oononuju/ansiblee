# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Dimension Data
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   - Aimon Bustardo <aimon.bustardo@dimensiondata.com>
#   - Mark Maglana   <mmaglana@gmail.com>
#   - Adam Friedman  <tintoy@tintoy.io>
#
# Common functionality to be used by versious module components

import os
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves import configparser
from os.path import expanduser
from uuid import UUID

try:
    from libcloud.common.dimensiondata import API_ENDPOINTS, DimensionDataAPIException, DimensionDataStatus
    from libcloud.compute.base import Node, NodeLocation
    from libcloud.compute.providers import get_driver
    from libcloud.compute.types import Provider

    import libcloud.security

    HAS_LIBCLOUD = True
except ImportError:
    libcloud = None
    API_ENDPOINTS, DimensionDataAPIException, DimensionDataStatus = None
    Node, NodeLocation = None
    get_driver = None
    Provider = None

    HAS_LIBCLOUD = False

# MCP 2.x version patten for location (datacenter) names.
#
# Note that this is not a totally reliable way of determining MCP version.
# Unfortunately, libcloud's NodeLocation currently makes no provision for extended properties.
# At some point we may therefore want to either enhance libcloud or enable overriding mcp_version
# by specifying it in the module parameters.
MCP_2_LOCATION_NAME_PATTERN = re.compile(r".*MCP\s?2.*")


class DimensionDataModule(object):
    """
    The base class containing common functionality used by Dimension Data modules for Ansible.
    """

    def __init__(self, module):
        """
        Create a new DimensionDataModule.

        Will fail if Apache libcloud is not present.

        :param module: The underlying Ansible module.
        :type module: AnsibleModule
        """

        self.module = module

        if not HAS_LIBCLOUD:
            self.module.fail_json(msg='libcloud is required for this module.')

            return

        # Credentials are common to all Dimension Data modules.
        credentials = self.get_credentials()
        self.user_id = credentials['user_id']
        self.key = credentials['key']

        # Region and location are common to all Dimension Data modules.
        if 'region' in self.module.params:
            region = self.module.params['region']
            self.region = 'dd-{}'.format(region)
        else:
            self.region = None

        if 'location' in self.module.params:
            self.location = self.module.params['location']
        else:
            self.location = None

        if 'verify_ssl_cert' in self.module.params:
            libcloud.security.VERIFY_SSL_CERT = self.module.params['verify_ssl_cert']

        self.driver = get_driver(Provider.DIMENSIONDATA)(
            self.user_id,
            self.key,
            region=self.region
        )

    def get_credentials(self):
        """
        Get user_id and key from module configuration, environment, or dotfile.
        Order of priority is module, environment, dotfile.

        To set in environment:

            export MCP_USER='myusername'
            export MCP_PASSWORD='mypassword'

        To set in dot file place a file at ~/.dimensiondata with
        the following contents:

            [dimensiondatacloud]
            MCP_USER: myusername
            MCP_PASSWORD: mypassword
        """

        if not HAS_LIBCLOUD:
            self.module.fail_json(msg='libcloud is required for this module.')

            return None

        user_id = None
        key = None

        # First, try the module configuration
        if 'mcp_user' in self.module.params:
            if 'mcp_password' not in self.module.params:
                self.module.fail_json(
                    msg='"mcp_user" parameter was specified, but not "mcp_password" (either both must be specified, or neither).'
                )

                return None

            user_id = self.module.params['mcp_user']
            key = self.module.params['mcp_password']

        # Fall back to environment
        if not user_id or not key:
            user_id = os.environ.get('MCP_USER', None)
            key = os.environ.get('MCP_PASSWORD', None)

        # Finally, try dotfile (~/.dimensiondata)
        if not user_id or not key:
            home = expanduser('~')
            config = configparser.RawConfigParser()
            config.read("%s/.dimensiondata" % home)

            try:
                user_id = config.get("dimensiondatacloud", "MCP_USER")
                key = config.get("dimensiondatacloud", "MCP_PASSWORD")
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass

        # One or more credentials not found. Function can't recover from this
        # so it has to raise an error instead of fail silently.
        if not user_id:
            raise MissingCredentialsError("Dimension Data user id not found")
        elif not key:
            raise MissingCredentialsError("Dimension Data key not found")

        # Both found, return data
        return dict(user_id=user_id, key=key)

    def get_mcp_version(self, location):
        """
        Get the MCP version for the specified location.
        """

        location = self.driver.ex_get_location_by_id(location)
        if MCP_2_LOCATION_NAME_PATTERN.match(location.name):
            return '2.0'

        return '1.0'

    def get_network_domain(self, locator, location):
        """
        Retrieve a network domain by its name or Id.
        """

        if is_uuid(locator):
            network_domain = self.driver.ex_get_network_domain(locator)
        else:
            matching_network_domains = [
                network_domain for network_domain in self.driver.ex_list_network_domains(location=location)
                if network_domain.name == locator
            ]

            if matching_network_domains:
                network_domain = matching_network_domains[0]
            else:
                network_domain = None

        if network_domain:
            return network_domain

        raise UnknownNetworkError("Network '%s' could not be found" % locator)

    def get_vlan(self, locator, location, network_domain):
        """
        Get a VLAN object by its name or id
        """
        if is_uuid(locator):
            vlan = self.driver.ex_get_vlan(locator)
        else:
            matching_vlans = [
                vlan for vlan in self.driver.ex_list_vlans(location, network_domain)
                if vlan.name == locator
            ]

            if matching_vlans:
                vlan = matching_vlans[0]
            else:
                vlan = None

        if vlan:
            return vlan

        raise UnknownVLANError("VLAN '%s' could not be found" % locator)


class LibcloudNotFound(Exception):
    """
    Exception raised when Apache libcloud cannot be found.
    """

    pass


class MissingCredentialsError(Exception):
    """
    Exception raised when credentials for Dimension Data CloudControl cannot be found.
    """

    pass


class UnknownNetworkError(Exception):
    """
    Exception raised when a network or network domain cannot be found.
    """

    pass


class UnknownVLANError(Exception):
    """
    Exception raised when a VLAN cannot be found.
    """

    pass


def get_dd_regions():
    """
    Get the list of available regions whose vendor is Dimension Data.
    """

    # Get endpoints
    all_regions = API_ENDPOINTS.keys()

    # Only Dimension Data endpoints (no prefix)
    regions = [region[3:] for region in all_regions if region.startswith('dd-')]

    return regions


def is_uuid(u, version=4):
    """
    Test if valid v4 UUID
    """
    try:
        uuid_obj = UUID(u, version=version)

        return str(uuid_obj) == u
    except ValueError:
        return False
