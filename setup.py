#from distutils.core import setup
from setuptools import setup

setup(
    name='graphitecollectors',
    author='Matt Hite',
    author_email='mhite@hotmail.com',
    description='A collection of network device graphite collectors',
    version='1.4.1',
    packages=['graphitecollectors',],
    scripts=['bin/f5-agent',],
    install_requires=['bigsuds', 'argparse',],
)
