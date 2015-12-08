#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="decofuzz",
    version="0.1",
    packages=["decofuzz"],
    author="tintinweb",
    author_email="tintinweb@oststrom.com",
    description=(
        "Decorator based fuzzing approach that turns any 3rd party python project into a fuzzer"),
    license="GPLv2",
    keywords=["Fuzzing","Fuzzing framework","General Purpose Fuzzer","Decorator"],
    url="https://github.com/tintinweb/decofuzz/",
    download_url="https://github.com/tintinweb/decofuzz/tarball/v0.1",
    long_description=read("README.rst") if os.path.isfile("README.rst") else read("README.md"),
    install_requires=[],
    package_data={
                  'decofuzz': ['decofuzz'],
                  },
)