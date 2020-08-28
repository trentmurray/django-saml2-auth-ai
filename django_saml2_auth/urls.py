from django.urls import re_path
from django.conf import settings
from .views import AcsView, Sso

app_name = "django_saml2_auth"

urlpatterns = [
    re_path(
        settings.SAML2_GLOBAL_CONFIG.get(
            'ACS_PATH_REGEX',
            r"^{endpoint_prefix}sso/acs/(?P<configuration_id>[a-z0-9\-]+)/$").format(
            endpoint_prefix=settings.SAML2_GLOBAL_CONFIG.get('ENDPOINT_PREFIX', '')
        ),
        AcsView.as_view(),
        name="acs"
    ),
    re_path(r"^sso/auth/(?P<configuration_id>[a-z0-9\-]+)/$", Sso.as_view(), name='sso-auth'),
    # re_path(r"^sso/slo/(?P<configuration_id>[a-z0-9\-]+)/$", Slo.as_view(), name='sso-slo'),
]
