from setuptools import setup

setup(name='funniest',
    version='0.1',
    description='Windows CMD based scanner',
	long_description='A friendly command line interface wrapper using WMI',
    url='https://github.com/heyglen/wmi-scanner',
    keywords='wmi windows scan',
    author='Glen Harmon',
    license='MIT',
    packages=['wmi-scanner'],
    classifiers=[
        'Development Status :: 3 - Alpha',
    ],
    install_requires=[
        'click',
        'ipaddress',
        'wmi',
    ],
    dependency_links=['https://github.com/heyglen/wmi-scanner/archive/master.zip']
    zip_safe=False)