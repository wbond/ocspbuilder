# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import re

from tests.test_ocsp_response_builder import OCSPResponseBuilderTests
from tests.test_ocsp_request_builder import OCSPRequestBuilderTests


test_classes = [OCSPResponseBuilderTests, OCSPRequestBuilderTests]


def run(matcher=None):
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_classes:
        if matcher:
            names = loader.getTestCaseNames(test_class)
            for name in names:
                if re.search(matcher, name):
                    suite.addTest(test_class(name))
        else:
            suite.addTest(loader.loadTestsFromTestCase(test_class))
    verbosity = 2 if matcher else 1
    unittest.TextTestRunner(verbosity=verbosity).run(suite)
