"""Execute unit tests using pytest."""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import sys
from .. import types as t

from ..util import (
    ANSIBLE_TEST_DATA_ROOT,
    display,
    find_python,
    get_available_python_versions,
    is_subdir,
    str_to_version,
    SubprocessError,
    REMOTE_ONLY_PYTHON_VERSIONS,
)

from ..util_common import (
    intercept_command,
    ResultType,
    handle_layout_messages,
    run_command,
)

from ..ansible_util import (
    ansible_environment,
    check_pyyaml,
)

from ..target import (
    walk_internal_targets,
    walk_units_targets,
)

from ..config import (
    UnitsConfig,
)

from ..coverage_util import (
    coverage_context,
)

from ..data import (
    data_context,
)

from ..executor import (
    AllTargetsSkipped,
    Delegate,
    get_changes_filter,
    install_command_requirements,
    SUPPORTED_PYTHON_VERSIONS,
)


def get_pytest_version(args, python_version):  # type: (EnvironmentConfig, str) -> t.Optional[t.Tuple[int]]
    """
    Returns the version of pytest if available, otherwise returns None.
    """

    python = find_python(python_version)

    stdout, _dummy = run_command(
        args,
        [python, os.path.join(ANSIBLE_TEST_DATA_ROOT, 'pytestcheck.py')],
        capture=True,
        always=True)

    result = json.loads(stdout)
    version = result.get('pytest_version')

    if version:
        return str_to_version(version)

    return None


def command_units(args):
    """
    :type args: UnitsConfig
    """
    handle_layout_messages(data_context().content.unit_messages)

    changes = get_changes_filter(args)
    require = args.require + changes
    include = walk_internal_targets(walk_units_targets(), args.include, args.exclude, require)

    paths = [target.path for target in include]
    remote_paths = [path for path in paths
                    if is_subdir(path, data_context().content.unit_module_path)
                    or is_subdir(path, data_context().content.unit_module_utils_path)]

    if not paths:
        raise AllTargetsSkipped()

    if args.python and args.python in REMOTE_ONLY_PYTHON_VERSIONS and not remote_paths:
        raise AllTargetsSkipped()

    if args.delegate:
        raise Delegate(require=changes, exclude=args.exclude)

    version_commands = []

    available_versions = sorted(get_available_python_versions(list(SUPPORTED_PYTHON_VERSIONS)).keys())

    for version in SUPPORTED_PYTHON_VERSIONS:
        # run all versions unless version given, in which case run only that version
        if args.python and version != args.python_version:
            continue

        if not args.python and version not in available_versions:
            display.warning("Skipping unit tests on Python %s due to missing interpreter." % version)
            continue

        if args.requirements_mode != 'skip':
            install_command_requirements(args, version)

        env = ansible_environment(args)

        cmd = [
            'pytest',
            '--boxed',
            '-r', 'a',
            '-n', str(args.num_workers) if args.num_workers else 'auto',
            '--color',
            'yes' if args.color else 'no',
            '-p', 'no:cacheprovider',
            '-c', os.path.join(ANSIBLE_TEST_DATA_ROOT, 'pytest.ini'),
            '--junit-xml', os.path.join(ResultType.JUNIT.path, 'python%s-units.xml' % version),
        ]

        if not data_context().content.collection:
            cmd.append('--durations=25')

        # added in pytest 4.5.0, which requires python 2.7+
        if version != '2.6':
            pytest_version = get_pytest_version(args, version)
            if pytest_version and pytest_version >= (4, 5, 0):
                cmd.append('--strict-markers')

        plugins = []

        if args.coverage:
            plugins.append('ansible_pytest_coverage')

        if data_context().content.collection:
            plugins.append('ansible_pytest_collections')

        if plugins:
            env['PYTHONPATH'] += ':%s' % os.path.join(ANSIBLE_TEST_DATA_ROOT, 'pytest/plugins')
            env['PYTEST_PLUGINS'] = ','.join(plugins)

        if args.collect_only:
            cmd.append('--collect-only')

        if args.verbosity:
            cmd.append('-' + ('v' * args.verbosity))

        if version in REMOTE_ONLY_PYTHON_VERSIONS:
            test_paths = remote_paths
        else:
            test_paths = paths

        if not test_paths:
            continue

        cmd.extend(test_paths)

        version_commands.append((version, cmd, env))

    if args.requirements_mode == 'only':
        sys.exit()

    for version, command, env in version_commands:
        check_pyyaml(args, version)

        display.info('Unit test with Python %s' % version)

        try:
            with coverage_context(args):
                intercept_command(args, command, target_name='units', env=env, python_version=version)
        except SubprocessError as ex:
            # pytest exits with status code 5 when all tests are skipped, which isn't an error for our use case
            if ex.status != 5:
                raise
