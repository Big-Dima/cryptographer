from django.urls import path

from web import views

urlpatterns = [
    path('', views.hesh, name='hesh'),
    path('symmetric', views.symmetric, name='symmetric'),
    path('asymmetric', views.asymmetric, name='asymmetric'),
    path('help', views.help_view, name='help'),
]
