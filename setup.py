from distutils.core import setup

setup(
    name='graphitecollectors',
    author='Matt Hite',
    author_email='mhite@hotmail.com',
    description='A collection of network device graphite collectors',
    version='1.0',
    packages=['graphitecollectors',],
    scripts=['bin/f5-agent', 'bin/juniper-agent', 'bin/srx-agent',],
    install_requires=['bigsuds', 'ecdsa', 'lxml', 'ncclient', 'paramiko',
                      'pycrypto', 'suds', 'wsgiref', 'xmltodict',],
)
