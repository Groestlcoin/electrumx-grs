import setuptools
from server.version import VERSION


setuptools.setup(
    name='electrumx-grs',
    version=VERSION.split()[-1],
    scripts=['electrumx_server.py', 'electrumx_rpc.py'],
    python_requires='>=3.5.3',
    # "irc" package is only required if IRC connectivity is enabled
    # via environment variables, in which case I've tested with 15.0.4
    # "groestlcoin_hash" package is required to sync GRS network.
    install_requires=['plyvel', 'pylru', 'irc', 'aiohttp >= 1', 'groestlcoin_hash'],
    dependency_links=['git+https://github.com/groestlcoin/groestlcoin-hash-python#egg=groestlcoin_hash'],
    packages=setuptools.find_packages(),
    description='ElectrumX-GRS Server',
    author='Kefkius',
    author_email='kefkius@gmail.com',
    license='MIT Licence',
    url='https://github.com/Groestlcoin/electrumx-grs',
    long_description='Server implementation for the Electrum wallet',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Internet',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
    ],
)
