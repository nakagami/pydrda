import sys
import unittest
from distutils.core import setup, Command


class TestCommand(Command):
    user_options = [('db=', None, 'database type (derby|db2)')]

    def initialize_options(self):
        self.db = 'derby'

    def finalize_options(self):
        assert self.db in ('derby', 'db2'), 'Invalid database type!'

    def run(self):
        if self.db == 'derby':
            from drda.tests import test_derby as test_module
        elif self.db == 'db2':
            from drda.tests import test_db2 as test_module
        unittest.main(test_module, argv=sys.argv[:1])

cmdclass = {'test': TestCommand}

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
    cmdclass=cmdclass,
    install_requires=['pyDes'],
)
