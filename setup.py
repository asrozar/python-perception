#!/usr/bin/python2
from setuptools import setup, find_packages

setup(
    # Application name:
    name="perception",

    # Version number (initial):
    version="0.6",

    # Application author details:
    author="Avery Rozar",
    author_email="avery.rozar@critical-sec.com",

    # Packages
    packages=find_packages(exclude=('tests', 'docs')),

    # Include additional files into the package
    include_package_data=True,

    # Details
    url="https://www.critical-sec/com/perception",

    #
    license="LICENSE.txt",
    description="",

    long_description=open("README.rst").read(),

    # Dependent packages (distributions)
    install_requires=['alembic',
                      'sqlalchemy',
                      'scapy',
                      'pyOpenSSL',
                      'psycopg2',
                      'cryptography',
                      'pexpect',
                      'pika',
                      'xlsxwriter',
                      'pytz',
                      'requests'
                      ])
