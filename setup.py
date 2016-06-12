import sys
from distutils.core import setup, Command


class TestCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        from drda.tests import test_derby
        import unittest
        unittest.main(test_derby, argv=sys.argv[:1])

cmdclass = {'test': TestCommand}

version = "%d.%d.%d" % __import__('drda').VERSION

classifiers = [
    'Development Status :: 2 - Pre-Alpha',
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
    keywords=['Apache Derby'],
    author='Hajime Nakagami',
    author_email='nakagami@gmail.com',
    description='DRDA protocol database driver',
    license="MIT",
    packages=['drda'],
    cmdclass=cmdclass,
)
