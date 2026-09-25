"""Importing the API catches undefined route dependencies before deployment."""

import importlib
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))


class ApiImportTests(unittest.TestCase):
    def test_scan_route_imports(self):
        main = importlib.import_module("main")
        routes = {(route.path, tuple(route.methods or ())) for route in main.app.routes}
        self.assertTrue(any(path == "/api/scans" and "POST" in methods for path, methods in routes))


if __name__ == "__main__":
    unittest.main()
