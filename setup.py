from distutils.core import setup

setup(
    # Application name:
    name="Perception",

    # Version number (initial):
    version="0.5",

    # Application author details:
    author="Avery Rozar",
    author_email="avery.rozar@critical-sec.com",

    # Packages
    packages=["perception"],

    # Include additional files into the package
    include_package_data=True,

    # Details
    url="https://www.critical-sec/com/perception",

    #
    license="LICENSE.txt",
    description="",

    long_description=open("README.md").read(),

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
                      'splunk-sdk',
                      'elasticsearch',
                      ],
)