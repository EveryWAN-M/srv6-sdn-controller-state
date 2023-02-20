# Always prefer setuptools over distutils
from setuptools import setup
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read version from VERSION file
with open(path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.
setup(
    name='srv6-sdn-controller-state',
    version=version,
    description='SRv6 SDN Control State',  # Required
    long_description=long_description,
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='',  # Optional
    packages=['srv6_sdn_controller_state'],  # Required
    install_requires=[
        'setuptools>=41.2.0',
        'pymongo'
    ]
)
