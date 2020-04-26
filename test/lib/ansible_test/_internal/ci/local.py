"""Support code for working without a supported CI provider."""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import platform
import random
import re

from .. import types as t

from ..config import (
    CommonConfig,
    TestConfig,
)

from ..io import (
    read_text_file,
)

from ..git import (
    Git,
)

from ..util import (
    ApplicationError,
    display,
    is_binary_file,
    SubprocessError,
)

from . import (
    AuthContext,
    CIProvider,
)

CODE = ''  # not really a CI provider, so use an empty string for the code


class Local(CIProvider):
    """CI provider implementation when not using CI."""
    priority = 1000

    @staticmethod
    def is_supported():  # type: () -> bool
        """Return True if this provider is supported in the current running environment."""
        return True

    @property
    def code(self):  # type: () -> str
        """Return a unique code representing this provider."""
        return CODE

    @property
    def name(self):  # type: () -> str
        """Return descriptive name for this provider."""
        return 'Local'

    def generate_resource_prefix(self):  # type: () -> str
        """Return a resource prefix specific to this CI provider."""
        node = re.sub(r'[^a-zA-Z0-9]+', '-', platform.node().split('.')[0]).lower()

        prefix = 'ansible-test-%s-%d' % (node, random.randint(10000000, 99999999))

        return prefix

    def get_base_branch(self):  # type: () -> str
        """Return the base branch or an empty string."""
        return ''

    def detect_changes(self, args):  # type: (TestConfig) -> t.Optional[t.List[str]]
        """Initialize change detection."""
        result = LocalChanges(args)

        display.info('Detected branch %s forked from %s at commit %s' % (
            result.current_branch, result.fork_branch, result.fork_point))

        if result.untracked and not args.untracked:
            display.warning('Ignored %s untracked file(s). Use --untracked to include them.' %
                            len(result.untracked))

        if result.committed and not args.committed:
            display.warning('Ignored %s committed change(s). Omit --ignore-committed to include them.' %
                            len(result.committed))

        if result.staged and not args.staged:
            display.warning('Ignored %s staged change(s). Omit --ignore-staged to include them.' %
                            len(result.staged))

        if result.unstaged and not args.unstaged:
            display.warning('Ignored %s unstaged change(s). Omit --ignore-unstaged to include them.' %
                            len(result.unstaged))

        names = set()

        if args.tracked:
            names |= set(result.tracked)
        if args.untracked:
            names |= set(result.untracked)
        if args.committed:
            names |= set(result.committed)
        if args.staged:
            names |= set(result.staged)
        if args.unstaged:
            names |= set(result.unstaged)

        if not args.metadata.changes:
            args.metadata.populate_changes(result.diff)

            for path in result.untracked:
                if is_binary_file(path):
                    args.metadata.changes[path] = ((0, 0),)
                    continue

                line_count = len(read_text_file(path).splitlines())

                args.metadata.changes[path] = ((1, line_count),)

        return sorted(names)

    def supports_core_ci_auth(self, context):  # type: (AuthContext) -> bool
        """Return True if Ansible Core CI is supported."""
        path = self._get_aci_key_path(context)
        return os.path.exists(path)

    def prepare_core_ci_auth(self, context):  # type: (AuthContext) -> t.Dict[str, t.Any]
        """Return authentication details for Ansible Core CI."""
        path = self._get_aci_key_path(context)
        auth_key = read_text_file(path).strip()

        request = dict(
            key=auth_key,
            nonce=None,
        )

        auth = dict(
            remote=request,
        )

        return auth

    def get_git_details(self, args):  # type: (CommonConfig) -> t.Optional[t.Dict[str, t.Any]]
        """Return details about git in the current environment."""
        return None  # not yet implemented for local

    def _get_aci_key_path(self, context):  # type: (AuthContext) -> str
        path = os.path.expanduser('~/.ansible-core-ci.key')

        if context.region:
            path += '.%s' % context.region

        return path


class InvalidBranch(ApplicationError):
    """Exception for invalid branch specification."""
    def __init__(self, branch, reason):  # type: (str, str) -> None
        message = 'Invalid branch: %s\n%s' % (branch, reason)

        super(InvalidBranch, self).__init__(message)

        self.branch = branch


class LocalChanges:
    """Change information for local work."""
    def __init__(self, args):  # type: (CommonConfig) -> None
        self.args = args
        self.git = Git()

        self.current_branch = self.git.get_branch()

        if self.is_official_branch(self.current_branch):
            raise InvalidBranch(branch=self.current_branch,
                                reason='Current branch is not a feature branch.')

        self.fork_branch = None
        self.fork_point = None

        self.local_branches = sorted(self.git.get_branches())
        self.official_branches = sorted([b for b in self.local_branches if self.is_official_branch(b)])

        for self.fork_branch in self.official_branches:
            try:
                self.fork_point = self.git.get_branch_fork_point(self.fork_branch)
                break
            except SubprocessError:
                pass

        if self.fork_point is None:
            raise ApplicationError('Unable to auto-detect fork branch and fork point.')

        # tracked files (including unchanged)
        self.tracked = sorted(self.git.get_file_names(['--cached']))
        # untracked files (except ignored)
        self.untracked = sorted(self.git.get_file_names(['--others', '--exclude-standard']))
        # tracked changes (including deletions) committed since the branch was forked
        self.committed = sorted(self.git.get_diff_names([self.fork_point, 'HEAD']))
        # tracked changes (including deletions) which are staged
        self.staged = sorted(self.git.get_diff_names(['--cached']))
        # tracked changes (including deletions) which are not staged
        self.unstaged = sorted(self.git.get_diff_names([]))
        # diff of all tracked files from fork point to working copy
        self.diff = self.git.get_diff([self.fork_point])

    @staticmethod
    def is_official_branch(name):  # type: (str) -> bool
        """Return True if the given branch name an official branch for development or releases."""
        if name == 'devel':
            return True

        if re.match(r'^stable-[0-9]+\.[0-9]+$', name):
            return True

        return False
