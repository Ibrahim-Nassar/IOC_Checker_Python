import importlib


def test_package_imports():
    # Ensure key modules import without ModuleNotFoundError due to wrong import paths
    importlib.import_module("IOC_Checker_Python.http_client")
    importlib.import_module("IOC_Checker_Python.providers_base")
    importlib.import_module("IOC_Checker_Python.abuseipdb_api")


