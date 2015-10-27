# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import unittest


_non_local = {'patched': False}


def patch():
    if not sys.version_info < (2, 7):
        return

    if _non_local['patched']:
        return

    unittest.TestCase.assertGreaterEqual = _assert_greater_equal
    unittest.TestCase.assertLess = _assert_less
    _non_local['patched'] = True


def _assert_greater_equal(self, a, b, msg=None):
    if not a >= b:
        standard_msg = '%s not greater than or equal to %s' % (unittest.util.safe_repr(a), unittest.util.safe_repr(b))
        self.fail(self._formatMessage(msg, standard_msg))


def _assert_less(self, a, b, msg=None):
    if not a < b:
        standard_msg = '%s not less than %s' % (unittest.util.safe_repr(a), unittest.util.safe_repr(b))
        self.fail(self._formatMessage(msg, standard_msg))
