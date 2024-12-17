# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
#
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

from __future__ import annotations

import os

from ansible import constants as C
from ansible.executor.task_executor import remove_omit
from ansible.playbook.handler import Handler
from ansible.template import Templar
from ansible.utils.display import Display

display = Display()


class IncludedFile:

    def __init__(self, filename, args, vars, task, is_role=False):
        self._filename = filename
        self._args = args
        self._vars = vars
        self._task = task
        self._hosts = []
        self._is_role = is_role
        self._results = []

    def add_host(self, host):
        if host not in self._hosts:
            self._hosts.append(host)
            return
        raise ValueError()

    def __eq__(self, other):
        return (other._filename == self._filename and
                other._args == self._args and
                other._vars == self._vars and
                other._task._uuid == self._task._uuid and
                other._task._parent._uuid == self._task._parent._uuid)

    def __repr__(self):
        return "%s (args=%s vars=%s): %s" % (self._filename, self._args, self._vars, self._hosts)

    @staticmethod
    def process_include_results(results, iterator, loader, variable_manager):
        included_files = []
        task_vars_cache = {}

        for res in results:

            original_host = res._host
            original_task = res._task

            if original_task.action in C._ACTION_ALL_INCLUDES:

                if original_task.loop:
                    if 'results' not in res._result:
                        continue
                    include_results = res._result['results']
                else:
                    include_results = [res._result]

                for include_result in include_results:
                    # if the task result was skipped or failed, continue
                    if 'skipped' in include_result and include_result['skipped'] or 'failed' in include_result and include_result['failed']:
                        continue

                    cache_key = (iterator._play, original_host, original_task)
                    try:
                        task_vars = task_vars_cache[cache_key]
                    except KeyError:
                        task_vars = task_vars_cache[cache_key] = variable_manager.get_vars(play=iterator._play, host=original_host, task=original_task)

                    include_args = include_result.pop('include_args', dict())
                    special_vars = {}
                    loop_var = include_result.get('ansible_loop_var', 'item')
                    index_var = include_result.get('ansible_index_var')
                    if loop_var in include_result:
                        task_vars[loop_var] = special_vars[loop_var] = include_result[loop_var]
                        task_vars['ansible_loop_var'] = special_vars['ansible_loop_var'] = loop_var
                    if index_var and index_var in include_result:
                        task_vars[index_var] = special_vars[index_var] = include_result[index_var]
                        task_vars['ansible_index_var'] = special_vars['ansible_index_var'] = index_var
                    if '_ansible_item_label' in include_result:
                        task_vars['_ansible_item_label'] = special_vars['_ansible_item_label'] = include_result['_ansible_item_label']
                    if 'ansible_loop' in include_result:
                        task_vars['ansible_loop'] = special_vars['ansible_loop'] = include_result['ansible_loop']
                    if original_task.no_log and '_ansible_no_log' not in include_args:
                        task_vars['_ansible_no_log'] = special_vars['_ansible_no_log'] = original_task.no_log

                    # get search path for this task to pass to lookup plugins that may be used in pathing to
                    # the included file
                    task_vars['ansible_search_path'] = original_task.get_search_path()

                    # ensure basedir is always in (dwim already searches here but we need to display it)
                    if loader.get_basedir() not in task_vars['ansible_search_path']:
                        task_vars['ansible_search_path'].append(loader.get_basedir())

                    templar = Templar(loader=loader, variables=task_vars)

                    if original_task.action in C._ACTION_INCLUDE_TASKS:
                        include_file = None
                        dirname = 'handlers' if isinstance(original_task, Handler) else 'tasks'
                        include_target = templar.template(include_result['include'])
                        candidates = [loader.path_dwim_relative(_path, dirname, include_target, is_role=True) for _path in task_vars['ansible_search_path']]
                        for include_file in candidates:
                            try:
                                # may throw OSError
                                os.stat(include_file)
                                # or select the task file if it exists
                                break
                            except OSError:
                                pass
                        else:
                            include_file = loader.path_dwim(include_target)

                        inc_file = IncludedFile(include_file, include_args, special_vars, original_task)
                    else:
                        # template the included role's name here
                        role_name = include_args.pop('name', include_args.pop('role', None))
                        if role_name is not None:
                            role_name = templar.template(role_name)

                        new_task = original_task.copy()
                        new_task.post_validate(templar=templar)
                        new_task._role_name = role_name
                        for from_arg in new_task.FROM_ARGS:
                            if from_arg in include_args:
                                from_key = from_arg.removesuffix('_from')
                                new_task._from_files[from_key] = templar.template(include_args.pop(from_arg))

                        omit_token = task_vars.get('omit')
                        if omit_token:
                            new_task._from_files = remove_omit(new_task._from_files, omit_token)

                        inc_file = IncludedFile(role_name, include_args, special_vars, new_task, is_role=True)

                    idx = 0
                    orig_inc_file = inc_file
                    while 1:
                        try:
                            pos = included_files[idx:].index(orig_inc_file)
                            # pos is relative to idx since we are slicing
                            # use idx + pos due to relative indexing
                            inc_file = included_files[idx + pos]
                        except ValueError:
                            included_files.append(orig_inc_file)
                            inc_file = orig_inc_file

                        try:
                            inc_file.add_host(original_host)
                            inc_file._results.append(res)
                        except ValueError:
                            # The host already exists for this include, advance forward, this is a new include
                            idx += pos + 1
                        else:
                            break

        return included_files
