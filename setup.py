import sys
import unittest
from setuptools import setup


version = "%d.%d.%d" % __import__('drda').VERSION

classifiers = [
    'Development Status :: 4 - Beta',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Topic :: Database',
]

setup(
    name="pydrda",
    version=version,
    url='https://github.com/nakagami/pydrda/',
    classifiers=classifiers,
    keywords=['Db2', 'Apache Derby'],
    author='Hajime Nakagami',
    author_email='nakagami@gmail.com',
    description='DRDA protocol database driver',
    long_description=open('README.rst').read(),
    license="MIT",
    packages=['drda'],
    install_requires=['pyDes'],
)
