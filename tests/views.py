from django.http import HttpResponse


def simple_test(request):
    return HttpResponse('Hello')


def test_app(request, path='/'):
    return HttpResponse('Path: %s' % path)
