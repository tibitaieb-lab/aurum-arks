"""Portable synthetic checks. All generated data live in a temporary directory."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]


def main():
    with tempfile.TemporaryDirectory(prefix='arks-public-') as folder:
        os.environ['ARKS_DOC_TEST_ROOT'] = folder
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in
                                   ('test_contracts', 'test_policy', 'test_provenance', 'test_documentary', 'test_public_demo'))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
