"""ADLeastCLI

This script for managing users/groups on Active Directory.
Very limited operations are available.
"""

import os, re
from setuptools import setup

ROOT = os.path.dirname(__file__)
def get_version():
    init = open(os.path.join(ROOT, "adleastcli.py")).read()
    return re.search(r"""__version__ = ['"]([\w\.-]+)['"]""", init).group(1)

setup(
    name             = "adleastcli",
    version          = get_version(),
    description      = "Simple user management CLI for Active Directory",
    long_description = open("README.rst").read(),
    author           = "Nobuo Okazaki",
    author_email     = "nobrin@biokids.org",
    url              = "https://github.com/nobrin/adleastcli",
    zip_safe         = False,
    install_requires = ["ldap3"],
    py_modules       = ["adleastcli"],
    scripts          = ["adleastcli"],
    license          = "MIT",
    platforms        = "any",
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)

