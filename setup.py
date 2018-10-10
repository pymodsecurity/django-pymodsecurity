from setuptools import setup

setup(
    name='django-pymodsecurity',
    version='0.0.1',
    description='Django middleware for ModSecurity.',
    url='https://github.com/GustavoKatel/django-pymodsecurity',
    author='GustavoKatel',
    author_email='gbritosampaio@gmail.com',
    license='MIT',
    packages=['django_pymodsecurity'],
    install_requires=[
        'Django',
    ],
    zip_safe=False)
