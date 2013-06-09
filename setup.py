#!/usr/bin/env python
#
# Copyright 2013, the py-Narrato authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from setuptools import setup

setup(
    name =          'py-narrato',
    version =       '0.1',
    description =   'Minimal Narrato API client for Python.',
    author =        'Narrato Team',
    author_email =  'team@narrato.co',
    license =       'Apache 2',
    url =           'http://github.com/narrato/py-narrato/',
    install_requires=[],
    py_modules =    ['narratoapi']
)
