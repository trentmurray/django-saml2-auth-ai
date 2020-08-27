from django.urls import path, re_path
from . import views

from .views import AscView

app_name = "django_saml2_auth"

urlpatterns = [
    re_path(r"^sso/acs/(?P<configuration_id>[a-z0-9\-]+)/$", AscView.as_view(), name="acs"),
    re_path(r"^sso/auth/$", Sso.as_view(), name='sso-auth'),
    re_path(r"^sso/slo/$", Slo.as_view(), name='sso-slo'),

]
