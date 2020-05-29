from django.http import HttpResponse

from django.template import loader


def hesh(request):
    template = loader.get_template('web/hesh.html')

    return HttpResponse(template.render({}, request))


def help_view(request):
    template = loader.get_template('web/help.html')

    return HttpResponse(template.render({}, request))


def symmetric(request):
    template = loader.get_template('web/symmetric.html')

    return HttpResponse(template.render({}, request))


def asymmetric(request):
    template = loader.get_template('web/asymmetric.html')

    return HttpResponse(template.render({}, request))
