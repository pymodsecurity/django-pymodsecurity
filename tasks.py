import glob
import os

from invoke import task

SOURCE_PATH = 'django_pymodsecurity'
TESTS_PATH = 'tests'


@task
def format(ctx, noimports=False, nostyle=False):
    if not noimports:
        from isort import SortImports

    if not nostyle:
        from yapf.yapflib.yapf_api import FormatFile

    for filename in glob.glob('**/*.py', recursive=True):
        if not noimports:
            SortImports(filename)
        if not nostyle:
            FormatFile(filename, in_place=True)


@task
def test(ctx, n='auto', m='1', debug=False, nocapture=False):
    import pytest
    args = [
        '-n=%s' % n,
        '-m=%s' % m,
    ]

    if debug:
        args.append('-vv')

    if nocapture:
        args.append('--capture=no')

    pytest.main(args)
