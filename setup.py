from setuptools import setup, find_packages

setup(
    name='hawk_eye',
    version='0.1.0',    
    description='A powerful scanner to scan your Filesystem, S3, MySQL, Redis, Google Cloud Storage and Firebase storage for PII and sensitive data.',
    url='e',
    author='Rohit Kumar',
    author_email='',
    packages=find_packages('src'), 
    package_dir={'': 'src'},
    entry_points={
        'console_scripts': [
            'hawk_eye=hawk_eye:main',
        ],
    },
    license='Apache License 2.0',
    install_requires=['pyyaml', 'rich', 'mysql-connector-python', 'redis', 'boto3'],

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: Apache License 2.0',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='pii secrets sensitive-data cybersecurity scanner',
)