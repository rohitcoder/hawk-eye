from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name='hawk_scanner',
    version='0.1.1',    
    description='A powerful scanner to scan your Filesystem, S3, MySQL, Redis, Google Cloud Storage and Firebase storage for PII and sensitive data.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/rohitcoder/hawk-eye',
    author='Rohit Kumar',
    author_email='',
    include_package_data=True,
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests', 'tests.*', 'release']),
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'hawk_scanner=hawk_scanner.main:main',
        ],
    },
    license='Apache License 2.0',
    install_requires=['pyyaml', 'rich', 'mysql-connector-python', 'redis', 'boto3'],
    extras_require={
        "dev": ["twine>=4.0.2"],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='pii secrets sensitive-data cybersecurity scanner',
)
