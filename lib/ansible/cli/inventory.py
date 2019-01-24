# Copyright: (c) 2017, Brian Coca <bcoca@ansible.com>
# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import optparse
from operator import attrgetter

from ansible import constants as C
from ansible import context
from ansible.cli import CLI
from ansible.cli.arguments import optparse_helpers as opt_help
from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.inventory.host import Host
from ansible.plugins.loader import vars_loader
from ansible.utils.vars import combine_vars
from ansible.utils.display import Display

display = Display()

INTERNAL_VARS = frozenset(['ansible_diff_mode',
                           'ansible_facts',
                           'ansible_forks',
                           'ansible_inventory_sources',
                           'ansible_limit',
                           'ansible_playbook_python',
                           'ansible_run_tags',
                           'ansible_skip_tags',
                           'ansible_verbosity',
                           'ansible_version',
                           'inventory_dir',
                           'inventory_file',
                           'inventory_hostname',
                           'inventory_hostname_short',
                           'groups',
                           'group_names',
                           'omit',
                           'playbook_dir', ])

BOX_DRAWINGS = {
    'ascii': {
        'light_horizontal': '-',
        'light_left_and_heavy_right': '-',
        'light_up_and_right': '`',
        'light_vertical': '|',
        'light_vertical_and_right': '+',
        'right_heavy_and_left_down_light': '+',
    },
    'unicode': {
        'light_horizontal': '\u2500',
        'light_left_and_heavy_right': '\u257c',
        'light_up_and_right': '\u2514',
        'light_vertical_and_right': '\u251c',
        'light_vertical': '\u2502',
        'right_heavy_and_left_down_light': '\u252e',
    },
}


class InventoryCLI(CLI):
    ''' used to display or dump the configured inventory as Ansible sees it '''

    ARGUMENTS = {'host': 'The name of a host to match in the inventory, relevant when using --list',
                 'group': 'The name of a group in the inventory, relevant when using --graph', }

    def __init__(self, args):

        super(InventoryCLI, self).__init__(args)
        self.vm = None
        self.loader = None
        self.inventory = None

    def init_parser(self):
        super(InventoryCLI, self).init_parser(
            usage='usage: %prog [options] [host|group]',
            epilog='Show Ansible inventory information, by default it uses the inventory script JSON format')

        opt_help.add_inventory_options(self.parser)
        opt_help.add_vault_options(self.parser)
        opt_help.add_basedir_options(self.parser)

        # remove unused default options
        self.parser.remove_option('--limit')
        self.parser.remove_option('--list-hosts')

        # Actions
        action_group = optparse.OptionGroup(self.parser, "Actions", "One of following must be used on invocation, ONLY ONE!")
        action_group.add_option("--list", action="store_true", default=False, dest='list', help='Output all hosts info, works as inventory script')
        action_group.add_option("--host", action="store", default=None, dest='host', help='Output specific host info, works as inventory script')
        action_group.add_option("--graph", action="store_true", default=False, dest='graph',
                                help='create inventory graph, if supplying pattern it must be a valid group name')
        self.parser.add_option_group(action_group)

        # graph
        self.parser.add_option("-y", "--yaml", action="store_true", default=False, dest='yaml',
                               help='Use YAML format instead of default JSON, ignored for --graph')
        self.parser.add_option('--toml', action='store_true', default=False, dest='toml',
                               help='Use TOML format instead of default JSON, ignored for --graph')
        self.parser.add_option("--vars", action="store_true", default=False, dest='show_vars',
                               help='Add vars to graph display, ignored unless used with --graph')
        self.parser.add_option("-u", "--unicode", action="store_true", default=False, dest='use_unicode',
                               help='Use unicode symbols for the tree drawing, ignored unless used with --graph')

        # list
        self.parser.add_option("--export", action="store_true", default=C.INVENTORY_EXPORT, dest='export',
                               help="When doing an --list, represent in a way that is optimized for export,"
                                    "not as an accurate representation of how Ansible has processed it")
        # self.parser.add_option("--ignore-vars-plugins", action="store_true", default=False, dest='ignore_vars_plugins',
        #                       help="When doing an --list, skip vars data from vars plugins, by default, this would include group_vars/ and host_vars/")

    def post_process_args(self, options, args):
        options, args = super(InventoryCLI, self).post_process_args(options, args)

        display.verbosity = options.verbosity
        self.validate_conflicts(options, vault_opts=True)

        # there can be only one! and, at least, one!
        used = 0
        for opt in (options.list, options.host, options.graph):
            if opt:
                used += 1
        if used == 0:
            raise AnsibleOptionsError("No action selected, at least one of --host, --graph or --list needs to be specified.")
        elif used > 1:
            raise AnsibleOptionsError("Conflicting options used, only one of --host, --graph or --list can be used at the same time.")

        # set host pattern to default if not supplied
        if len(args) > 0:
            options.pattern = args[0]
        else:
            options.pattern = 'all'

        return options, args

    def run(self):

        super(InventoryCLI, self).run()

        # Initialize needed objects
        self.loader, self.inventory, self.vm = self._play_prereqs()

        results = None
        if context.CLIARGS['host']:
            hosts = self.inventory.get_hosts(context.CLIARGS['host'])
            if len(hosts) != 1:
                raise AnsibleOptionsError("You must pass a single valid host to --host parameter")

            myvars = self._get_host_variables(host=hosts[0])
            self._remove_internal(myvars)

            # FIXME: should we template first?
            results = self.dump(myvars)

        elif context.CLIARGS['graph']:
            results = self.inventory_graph()
        elif context.CLIARGS['list']:
            top = self._get_group('all')
            if context.CLIARGS['yaml']:
                results = self.yaml_inventory(top)
            elif context.CLIARGS['toml']:
                results = self.toml_inventory(top)
            else:
                results = self.json_inventory(top)
            results = self.dump(results)

        if results:
            # FIXME: pager?
            display.display(results)
            exit(0)

        exit(1)

    @staticmethod
    def dump(stuff):

        if context.CLIARGS['yaml']:
            import yaml
            from ansible.parsing.yaml.dumper import AnsibleDumper
            results = yaml.dump(stuff, Dumper=AnsibleDumper, default_flow_style=False)
        elif context.CLIARGS['toml']:
            from ansible.plugins.inventory.toml import toml_dumps, HAS_TOML
            if not HAS_TOML:
                raise AnsibleError(
                    'The python "toml" library is required when using the TOML output format'
                )
            results = toml_dumps(stuff)
        else:
            import json
            from ansible.parsing.ajson import AnsibleJSONEncoder
            results = json.dumps(stuff, cls=AnsibleJSONEncoder, sort_keys=True, indent=4)

        return results

    # FIXME: refactor to use same for VM
    def get_plugin_vars(self, path, entity):

        data = {}

        def _get_plugin_vars(plugin, path, entities):
            data = {}
            try:
                data = plugin.get_vars(self.loader, path, entity)
            except AttributeError:
                try:
                    if isinstance(entity, Host):
                        data = combine_vars(data, plugin.get_host_vars(entity.name))
                    else:
                        data = combine_vars(data, plugin.get_group_vars(entity.name))
                except AttributeError:
                    if hasattr(plugin, 'run'):
                        raise AnsibleError("Cannot use v1 type vars plugin %s from %s" % (plugin._load_name, plugin._original_path))
                    else:
                        raise AnsibleError("Invalid vars plugin %s from %s" % (plugin._load_name, plugin._original_path))
            return data

        for plugin in vars_loader.all():
            data = combine_vars(data, _get_plugin_vars(plugin, path, entity))

        return data

    def _get_group_variables(self, group):

        # get info from inventory source
        res = group.get_vars()

        # FIXME: add switch to skip vars plugins, add vars plugin info
        for inventory_dir in self.inventory._sources:
            res = combine_vars(res, self.get_plugin_vars(inventory_dir, group))

        if group.priority != 1:
            res['ansible_group_priority'] = group.priority

        return res

    def _get_host_variables(self, host):

        if context.CLIARGS['export']:
            hostvars = host.get_vars()

            # FIXME: add switch to skip vars plugins
            # add vars plugin info
            for inventory_dir in self.inventory._sources:
                hostvars = combine_vars(hostvars, self.get_plugin_vars(inventory_dir, host))
        else:
            hostvars = self.vm.get_vars(host=host, include_hostvars=False)

        return hostvars

    def _get_group(self, gname):
        group = self.inventory.groups.get(gname)
        return group

    @staticmethod
    def _remove_internal(dump):

        for internal in INTERNAL_VARS:
            if internal in dump:
                del dump[internal]

    @staticmethod
    def _remove_empty(dump):
        # remove empty keys
        for x in ('hosts', 'vars', 'children'):
            if x in dump and not dump[x]:
                del dump[x]

    def _show_vars(self, dump, depth, levels):
        result = []

        self._remove_internal(dump)

        if context.CLIARGS['show_vars']:
            sorted_vars = sorted(dump.items())

            for item in sorted_vars:
                levels[-1] = (item == sorted_vars[-1])

                result.append(self._graph_name(
                    '%s%s{ %s = %s }' % (
                        self._get_symbol('light_horizontal') * 2,
                        self._get_symbol('light_left_and_heavy_right'),
                        item[0], item[1]),
                    depth, levels))

        return result

    @staticmethod
    def _get_symbol(name):
        ret = None

        if context.CLIARGS['use_unicode']:
            box_charset = 'unicode'
        else:
            box_charset = 'ascii'

        if name in BOX_DRAWINGS[box_charset]:
            ret = BOX_DRAWINGS[box_charset][name]

        return ret

    def _graph_name(self, name, depth=0, levels=None):
        ret = ''

        if levels is None:
            levels = []

        if depth:
            levels_len = len(levels)

            for i, last in enumerate(levels):
                if i < levels_len - 1:
                    if last:
                        ret += "   "
                    else:
                        ret += "  %s" % self._get_symbol('light_vertical')
                else:
                    if last:
                        ret += "  %s%s" % (self._get_symbol('light_up_and_right'), name)
                    else:
                        ret += "  %s%s" % (self._get_symbol('light_vertical_and_right'), name)
        else:
            ret = name

        return ret

    def _graph_group(self, group, depth=0, levels=None):
        if levels is None:
            levels = []

        if group.child_groups or group.hosts or self._get_group_variables(group):
            last_deco_bit = self._get_symbol('right_heavy_and_left_down_light')
        else:
            last_deco_bit = self._get_symbol('light_left_and_heavy_right')

        decorated_group_name = '%s%s @%s:' % (self._get_symbol('light_horizontal') * 2, last_deco_bit, group.name)
        result = [self._graph_name(decorated_group_name, depth, levels)]
        depth = depth + 1
        levels.append(None)

        sorted_child_groups = sorted(group.child_groups, key=attrgetter('name'))

        for kid in sorted_child_groups:
            if kid == sorted_child_groups[-1] and not self._get_group_variables(group):
                levels[-1] = True
            else:
                levels[-1] = False

            result.extend(self._graph_group(kid, depth, list(levels)))

        if group.name != 'all':
            sorted_hosts = sorted(group.hosts, key=attrgetter('name'))

            for host in sorted_hosts:
                levels[-1] = (host == sorted_hosts[-1])

                host_vars = dict(host.get_vars())
                self._remove_internal(host_vars)

                if host_vars:
                    last_deco_bit = self._get_symbol('right_heavy_and_left_down_light')
                else:
                    last_deco_bit = self._get_symbol('light_left_and_heavy_right')

                decorated_host_name = "%s%s %s" % (
                    self._get_symbol('light_horizontal') * 2,
                    last_deco_bit,
                    host.name)
                result.append(self._graph_name(decorated_host_name, depth, levels))
                result.extend(self._show_vars(host.get_vars(), depth + 1, levels + [False]))

        result.extend(self._show_vars(self._get_group_variables(group), depth, levels))

        return result

    def inventory_graph(self):

        start_at = self._get_group(context.CLIARGS['pattern'])
        if start_at:
            return '\n'.join(self._graph_group(start_at))
        else:
            raise AnsibleOptionsError("Pattern must be valid group name when using --graph")

    def json_inventory(self, top):

        seen = set()

        def format_group(group):
            results = {}
            results[group.name] = {}
            if group.name != 'all':
                results[group.name]['hosts'] = [h.name for h in sorted(group.hosts, key=attrgetter('name'))]
            results[group.name]['children'] = []
            for subgroup in sorted(group.child_groups, key=attrgetter('name')):
                results[group.name]['children'].append(subgroup.name)
                if subgroup.name not in seen:
                    results.update(format_group(subgroup))
                    seen.add(subgroup.name)
            if context.CLIARGS['export']:
                results[group.name]['vars'] = self._get_group_variables(group)

            self._remove_empty(results[group.name])
            if not results[group.name]:
                del results[group.name]

            return results

        results = format_group(top)

        # populate meta
        results['_meta'] = {'hostvars': {}}
        hosts = self.inventory.get_hosts()
        for host in hosts:
            hvars = self._get_host_variables(host)
            if hvars:
                self._remove_internal(hvars)
                results['_meta']['hostvars'][host.name] = hvars

        return results

    def yaml_inventory(self, top):

        seen = []

        def format_group(group):
            results = {}

            # initialize group + vars
            results[group.name] = {}

            # subgroups
            results[group.name]['children'] = {}
            for subgroup in sorted(group.child_groups, key=attrgetter('name')):
                if subgroup.name != 'all':
                    results[group.name]['children'].update(format_group(subgroup))

            # hosts for group
            results[group.name]['hosts'] = {}
            if group.name != 'all':
                for h in sorted(group.hosts, key=attrgetter('name')):
                    myvars = {}
                    if h.name not in seen:  # avoid defining host vars more than once
                        seen.append(h.name)
                        myvars = self._get_host_variables(host=h)
                        self._remove_internal(myvars)
                    results[group.name]['hosts'][h.name] = myvars

            if context.CLIARGS['export']:
                gvars = self._get_group_variables(group)
                if gvars:
                    results[group.name]['vars'] = gvars

            self._remove_empty(results[group.name])

            return results

        return format_group(top)

    def toml_inventory(self, top):
        seen = set()
        has_ungrouped = bool(next(g.hosts for g in top.child_groups if g.name == 'ungrouped'))

        def format_group(group):
            results = {}
            results[group.name] = {}

            results[group.name]['children'] = []
            for subgroup in sorted(group.child_groups, key=attrgetter('name')):
                if subgroup.name == 'ungrouped' and not has_ungrouped:
                    continue
                if group.name != 'all':
                    results[group.name]['children'].append(subgroup.name)
                results.update(format_group(subgroup))

            if group.name != 'all':
                for host in sorted(group.hosts, key=attrgetter('name')):
                    if host.name not in seen:
                        seen.add(host.name)
                        host_vars = self._get_host_variables(host=host)
                        self._remove_internal(host_vars)
                    else:
                        host_vars = {}
                    try:
                        results[group.name]['hosts'][host.name] = host_vars
                    except KeyError:
                        results[group.name]['hosts'] = {host.name: host_vars}

            if context.CLIARGS['export']:
                results[group.name]['vars'] = self._get_group_variables(group)

            self._remove_empty(results[group.name])
            if not results[group.name]:
                del results[group.name]

            return results

        results = format_group(top)

        return results
