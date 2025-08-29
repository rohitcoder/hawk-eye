VERSION = "0.3.39"

from setuptools import setup, find_packages

with open("readme.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requires = f.read().splitlines()

setup(
    name='hawk_scanner',
    version=VERSION,   
    description='A powerful scanner to scan your Filesystem, S3, MongoDB, MySQL, PostgreSQL, Redis, Slack, Google Cloud Storage and Firebase storage for PII and sensitive data using text and OCR analysis. Hawk-eye can also analyse supports most of the file types like docx, xlsx, pptx, pdf, jpg, png, gif, zip, tar, rar, etc.',
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
    install_requires=requires,
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
