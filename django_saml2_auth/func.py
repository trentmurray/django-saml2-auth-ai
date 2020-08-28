from django.conf import settings

from django.http.request import HttpRequest
from django.shortcuts import redirect
from collections import Mapping

from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
)

from .models import Configuration


def get_default_next_url():
    configured_next_url = settings.SAML2_GLOBAL_CONFIG.get('DEFAULT_NEXT_URL', None)
    return configured_next_url if configured_next_url else redirect('/')


def merge_dict(dict1, dict2):
    for dict2_key, dict2_value in dict2.items():
        dict1_value = dict1.get(dict2_key)

        if isinstance(dict1_value, Mapping) and isinstance(dict2_value, Mapping):
            merge_dict(dict1_value, dict2_value)
        else:
            dict1[dict2_key] = dict2_value


def get_saml_client(request: HttpRequest, configuration: Configuration):
    acs_url = "{scheme}://{host}/{endpoint_prefix}sso/acs/{configuration_id}/".format(
        scheme="https" if request.is_secure() else "http",
        host=request.get_host(),
        endpoint_prefix=settings.SAML2_GLOBAL_CONFIG.get('ENDPOINT_PREFIX', ''),
        configuration_id=str(configuration.uuid)
    )

    saml_settings = {
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ]
                }
            },
            'allow_unsolicited': True,
            'authn_requests_signed': False,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'want_response_signed': False
        }
    }

    merge_dict(saml_settings, settings.SAML2_GLOBAL_CONFIG.get('SAML_CLIENT_SETTINGS'))

    sp_config = Saml2Config()
    sp_config.load(saml_settings)
    sp_config.allow_unknown_attributes = True

    return Saml2Client(config=sp_config)


