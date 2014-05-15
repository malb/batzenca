from distutils.core import setup

setup(
    name = 'BatzenCA',
    version = '0.1',
    packages = ['batzenca', 'batzenca/database'],
    scripts = ['scripts/batzenca-interactive.py', 'scripts/batzenca-release.py'],
    license = 'Simplified BSD License',
    long_description=open('README.rst').read(),
    author = 'Martin R. Albrecht',
    author_email = 'martinralbrech+batzenca@googlemail.com',
    url = 'https://bitbucket.org/malb/batzenca',
    install_requires = open("requirements.txt").read().split("\n"),
)