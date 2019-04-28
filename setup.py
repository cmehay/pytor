#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup

setup(
    name='pytor',

    version='0.1.3',

    packages=find_packages(),

    author="Christophe Mehay",

    author_email="cmehay@nospam.student.42.fr",

    description="Manage Tor hidden services keys",

    include_package_data=True,

    url='http://github.com/cmehay/pytor',

    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 1 - Planning",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],

    install_requires=['pycryptodome==3.8.1'],

    entry_points={
        'console_scripts': [
            'pytor = pytor.__main__:main',
        ],
    },

    license="WTFPL",
)
