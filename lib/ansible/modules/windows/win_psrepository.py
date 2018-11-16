#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Wojciech Sciesinski <wojciech[at]sciesinski[dot]net>
# Copyright: (c) 2017, Daniele Lazzari <lazzari@mailup.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# this is a windows documentation stub.  actual code lives in the .ps1
# file of the same name

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: win_psrepository
version_added: "2.8"
short_description: Adds, removes or updates a Windows PowerShell repository.
description:
  - This module helps to install, remove and update Windows PowerShell repository on Windows-based systems.
options:
  name:
    description:
      - Name of the repository to work with.
    aliases:
      - repository
    required: yes
  source_location:
    description:
      - URL of the custom repository to register.
    aliases:
      - url
  state:
    description:
      - If C(present) a new repository is added or existing updated.
      - If C(absent) a repository is removed.
    choices: [ absent, present ]
    default: present
  installation_policy:
    description:
      - If present than property InstallationPolicy of the new or existing repository will be set using it.
    choices: [ trusted, untrusted ]
    default: trusted
notes:
  - Windows PowerShell 5.0 or higher is needed.
  - The NuGet package provider version 2.8.5.201 or newer is required.
  - You can't use M(win_psrepository) to re-register (add) removed PSGallery, use the command `Register-PSRepository -Default` instead.
author:
- Wojciech Sciesinski (@it-praktyk)
- Daniele Lazzari (@dlazz)
'''

EXAMPLES = '''
---
- name: Add a PowerShell module and register a repository
  win_psrepository:
    name: MyRepository
    source_location: https://myrepo.com
    state: present

- name: Remove a PowerShell repository
  win_psrepository:
    name: MyRepository
    state: absent

- name: Set InstallationPolicy to trusted
  win_psrepository:
    name: PSGallery
    installation_policy: trusted
'''

RETURN = '''
---
output:
  description: A message describing the task result.
  returned: always
  sample: "The repository MyInternal with the SourceLocation https://repo.example.com/api/v2 was registred."
  type: string
'''
