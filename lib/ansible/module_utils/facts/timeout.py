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

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import signal
from functools import partial

# timeout function to make sure some fact gathering
# steps do not exceed a time limit

GATHER_TIMEOUT = None
DEFAULT_GATHER_TIMEOUT = 10


try:
    # On Python 3, reuse the TimeoutError
    class TimeoutError(TimeoutError):
        pass
except NameError:
    # On Python 2, there unfortunately isn't a better base class to inherit from
    class TimeoutError(Exception):
        pass


class _InternalTimeoutSignal(BaseException):
    """This is only used by the timeout decorator itself.  Do not use this elsewhere"""
    pass


def _handle_timeout(timeout_value, signum, frame):
    msg = 'Timer expired after %s seconds' % timeout_value
    raise _InternalTimeoutSignal(msg)


def timeout(seconds=None, error_message="Timer expired"):
    def decorator(func):
        def wrapper(*args, **kwargs):
            timeout_value = seconds
            if timeout_value is None:
                timeout_value = globals().get('GATHER_TIMEOUT') or DEFAULT_GATHER_TIMEOUT

            old_handler = signal.signal(signal.SIGALRM, partial(_handle_timeout, timeout_value))
            signal.alarm(timeout_value)

            try:
                result = func(*args, **kwargs)
            except _InternalTimeoutSignal as e:
                raise TimeoutError(e.args[0])
            finally:
                signal.signal(signal.SIGALRM, old_handler)
                signal.alarm(0)

            return result

        return wrapper

    # If we were called as @timeout, then the first parameter will be the
    # function we are to wrap instead of the number of seconds.  Detect this
    # and correct it by setting seconds to our default value and return the
    # inner decorator function manually wrapped around the function
    if callable(seconds):
        func = seconds
        seconds = None
        return decorator(func)

    # If we were called as @timeout([...]) then python itself will take
    # care of wrapping the inner decorator around the function

    return decorator
