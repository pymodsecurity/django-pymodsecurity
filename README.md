# django-pymodsecurity

[![Build Status](https://travis-ci.org/GustavoKatel/django-pymodsecurity.svg?branch=master)](https://travis-ci.org/GustavoKatel/django-pymodsecurity)
[![Codecov](https://img.shields.io/codecov/c/github/GustavoKatel/django-pymodsecurity.svg)](https://codecov.io/gh/GustavoKatel/django-pymodsecurity)

## This is a work-in-progress. Do not use in production

This middleware adds the modsecurity capabilities to the django framework.

## Dependencies

- pymodsecurity >= 0.0.4
- django >= 2.1.2

## HOWTO

Install the middleware in your django settings module. It's highly recommended to install at the first position, so all requests and responses can be approved by `modsecurity`.

```python
MIDDLEWARE = [
  > 'django_pymodsecurity.middleware.PyModSecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    ...
]
```

## Settings

Valid settings you can define in your `settings` django module

### MODSECURITY_RULE_FILES

You can specify a list of rule set to be imported (For example [owasp top10](https://github.com/SpiderLabs/owasp-modsecurity-crs)).

It accepts a list of files or `glob`-like patterns

```python
MODSECURITY_RULE_FILES = [
    '/data/config-logs.conf',
    '/data/owasp/*.conf'
]
```

### MODSECURITY_RULES

You can also define rules directly to be loaded into `modsecurity`. It can be a list of `strings` or a single `string`

```python
MODSECURITY_RULES = [
    'SecRuleEngine DetectionOnly',
    'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "phase:0,allow,id:161"'
]
```

```python
MODSECURITY_RULES = '''
SecRuleEngine DetectionOnly
SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "phase:0,allow,id:161"
'''
```

## License

MIT License
