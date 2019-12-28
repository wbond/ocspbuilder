# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os


package_name = "ocspbuilder"

other_packages = []

requires_oscrypto = True
has_tests_package = False

package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
build_root = os.path.abspath(os.path.join(package_root, '..'))

md_source_map = {
    'docs/api.md': ['ocspbuilder/__init__.py'],
}

definition_replacements = {}
