from distutils.core import setup
setup(
  name = 'steelhead_socks_proxy',
  packages = ['steelhead_socks_proxy'],
  version = '0.1',
  license='MIT',
  description = 'Pure-Python SOCKS5 intercepting proxy',
  author = 'mirror12k',
  url = 'https://github.com/mirror12k/Steelhead-SOCKS5-Proxy',
  download_url = 'https://github.com/mirror12k/Steelhead-SOCKS5-Proxy/archive/v_01.tar.gz',
  keywords = ['SOCKS', 'SOCKS5', 'proxy', 'intercept'],
  install_requires=[],
  classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3.8',
  ],
)