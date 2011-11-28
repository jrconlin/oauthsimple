#!env python

from setuptools import setup

setup(
    name='oauthsimple',
    version='1.0',
    description='Simple OAuth 1.0 signature generator',
    author='JR Conlin',
    author_email='jrconlin+oauthsimple@gmail.com',
    url='https://github.com/jrconlin/oauthsimple',
    packages=['OAuthSimple'],
    long_description=""""
    Generate OAuth 1.0 signatures easily. See the URL for details and examples.
    """,
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Develoipers",
        "Topic :: Internet"],
    keywords='networking oauth authorization',
    license='BSD',
    install_requires=[],
    )
