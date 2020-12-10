#!/usr/bin/env python3
import os, sys
from setuptools import setup, find_packages

setup(name='lumina',
      version='0.1',
      description='IDA lumina offline server',
      author='Synacktiv',
      author_email='johan.bonvicini@synacktiv.com',
      packages=find_packages(exclude=["tests"]),
      package_data={"lumina": [""]},
      test_suite="tests",
      scripts=[],
      install_requires=["construct"],
      entry_points={
          'console_scripts' : ['lumina_server=lumina.lumina_server:main']
      })