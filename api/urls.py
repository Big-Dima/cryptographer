from django.urls import path

from api import views

urlpatterns = [
    path('md5', views.get_md5, name='md5'),
    path('sha1', views.get_sha1, name='sha1'),
    path('sha224', views.get_sha224, name='sha224'),
    path('sha256', views.get_sha256, name='sha256'),
    path('sha384', views.get_sha384, name='sha384'),
    path('sha512', views.get_sha512, name='sha512'),
    path('des_encode', views.des_encode, name='des_encode'),
    path('des_decode', views.des_decode, name='des_decode'),
    path('rsa_generate_key', views.rsa_generate_key, name='rsa_generate_key'),
    path('rsa_encode', views.rsa_encode, name='rsa_encode'),
    path('rsa_decode', views.rsa_decode, name='rsa_decode'),
]
