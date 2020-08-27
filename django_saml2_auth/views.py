import urllib.parse as _urlparse
from urllib.parse import unquote

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django import get_version
from django.shortcuts import redirect
from pkg_resources import parse_version
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.template import TemplateDoesNotExist
from django.utils.http import is_safe_url
from django.utils.module_loading import import_string
from django.urls import reverse

from django.views.generic import CreateView, ListView
from django.http.response import HttpResponse

from saml2.ident import code, decode
from saml2.response import StatusAuthnFailed


from .func import get_saml_client
from .models import Configuration

import collections

user_model = get_user_model()


class AscView(CreateView):

    def set_subject_id(self, subject_id):
        self.request.session["_saml2_subject_id"] = code(subject_id)

    def get_subject_id(self):
        return decode(self.request.session.get('_saml2_subject_id', None))

    @staticmethod
    def get_location(http_info):
        headers = dict(http_info["headers"])
        return headers.get('Location', http_info.get('url'))

    @staticmethod
    def create_user(user_identity):
        attributes_map = settings.SAML2_GLOBAL_CONFIG.get("ATTRIBUTES_MAP", {})
        user_name = user_identity[attributes_map.get("user_identifier", "UserName")][0]
        user = user_model.objects.create_user(user_name)
        
        for (user_attr, saml_attr) in attributes_map.items():
            if user_attr != "username":
                values = user_identity.get(saml_attr)
                if values is not None:
                    setattr(user, user_attr, values[0])

        groups = [
            Group.objects.get(name=x)
            for x in settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get("USER_GROUPS", [])
        ]

        user.groups.set(groups)

        user.is_active = settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get(
            "ACTIVE_STATUS", True
        )
        user.is_staff = settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get(
            "STAFF_STATUS", True
        )
        user.is_superuser = settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get(
            "SUPERUSER_STATUS", False
        )

        if settings.SAML2_GLOBAL_CONFIG.get("TRIGGER", {}).get("NEW_USER", None):
            import_string(settings.SAML2_GLOBAL_CONFIG["TRIGGER"]["NEW_USER"])(user, user_identity)

        user.save()
        return user

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        configuration_id = kwargs.get('configuration_id')

        # Make sure the SAML response has come in on a valid ACS
        configuration = None
        if configuration_id:
            configuration = Configuration.objects.filter(uuid=configuration_id).first()

        if not configuration_id or not configuration:
            return HttpResponse(status=400, content_type='application/json', content={"error": "Invalid ACS endpoint"})

        saml_response = request.POST.get('SAMLResponse')
        next_url = request.session.get("login_next_url", get_default_next_url())

        if not saml_response:
            return HttpResponseRedirect(redirect_to=settings.SAML2_GLOBAL_CONFIG.get('INVALID_SAML_RESPONSE_URL'))

        # Parsing the response throws `StatusAuthnFailed` exception on user related
        # authentication errors (such as user canceling the authentication), so
        # deny access if that happens.
        saml_client = get_saml_client(request, configuration)

        try:
            authn_response = saml_client.parse_authn_request_response(
                saml_response, entity.BINDING_HTTP_POST,
            )
        except StatusAuthnFailed:
            authn_response = None

        if authn_response is None:
            return HttpResponseRedirect(redirect_to=settings.SAML2_GLOBAL_CONFIG.get('INVALID_SAML_RESPONSE_URL'))

        session_info = authn_response.session_info()
        user_identity = authn_response.get_identity()

        if user_identity is None:
            return HttpResponseRedirect(redirect_to=settings.SAML2_GLOBAL_CONFIG.get('INVALID_SAML_RESPONSE_URL'))

        user_identifier = settings.SAML2_GLOBAL_CONFIG.get("ATTRIBUTES_MAP", {}).get("user_identifier", "UserName")
        user_identifier_value = user_identity[
            settings.SAML2_GLOBAL_CONFIG.get("ATTRIBUTES_MAP", {}).get("login_identifier", "UserName")
        ][0]

        # Check to see if the user exists.

        is_new_user = False
        target_user = user_model.objects.filter(**{
            user_identifier: user_identifier_value
        }).first()

        # Trash the current session and start rebuilding it.
        request.session.flush()
        self.set_subject_id(session_info['name_id'])

        # If you have custom login processes, we pass this request over to it now.
        forward_auth = settings.SAML2_GLOBAL_CONFIG.get("FORWARD_AUTH_TO_CUSTOM_METHOD")

        if forward_auth:
            import_string(forward_auth)(target_user, user_identity)

            # We expect your code to take it from here, including user creation. If this returns, it means you have
            # not handled the response. We will prevent them from being logged in, and will trash the session for
            # security reasons.
            request.session.flush()
            logout(request)
            return HttpResponseRedirect(redirect_to=settings.SAML2_GLOBAL_CONFIG.get('INVALID_SAML_RESPONSE_URL'))

        if not target_user:
            self.create_user(user_identity)
            is_new_user = True

        # Make sure the user is active before logging them in.
        if target_user.is_active:
            target_user.backend = "django.contrib.auth.backends.ModelBackend"
            login(request, target_user)
        else:
            return HttpResponseRedirect(redirect_to=settings.SAML2_GLOBAL_CONFIG.get('USER_INACTIVE_URL'))

        # If it's a new user, we show the welcome page if it exists, otherwise just redirect them to the next url.
        if is_new_user:
            try:
                return render(request, "django_saas_sso/welcome.html", {"user": request.user})
            except TemplateDoesNotExist:
                return HttpResponseRedirect(next_url)
        else:
            return HttpResponseRedirect(next_url)


class Sso(CreateView):

    def post(self, request, *args, **kwargs):
        pass


class Slo(ListView):

    def get(self, request, *args, **kwargs):
        pass




def get_reverse(objs):
    if objs.__class__.__name__ not in ["list", "tuple"]:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass

    raise Exception(
        (
            "We got a URL reverse issue: %s. "
            "This is a known issue but please still submit a ticket at "
            "https://github.com/andersinno/django-saml2-auth-ai/issues/new"
        )
        % str(objs)
    )


def _merge_dict(d1, d2):
    for k, v2 in d2.items():
        v1 = d1.get(k)
        if isinstance(v1, collections.Mapping) and isinstance(v2, collections.Mapping):
            _merge_dict(v1, v2)
        else:
            d1[k] = v2


def _get_saml_client(domain):
    acs_url = domain + get_reverse([acs, "acs", "django_SAML2_GLOBAL_CONFIG:acs"])

    saml_settings = {
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                    ],
                },
                "allow_unsolicited": True,
                "authn_requests_signed": False,
                "logout_requests_signed": True,
                "want_assertions_signed": True,
                "want_response_signed": False,
            },
        },
    }

    _merge_dict(saml_settings, settings.SAML2_GLOBAL_CONFIG["SAML_CLIENT_SETTINGS"])

    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


def _set_subject_id(session, subject_id):
    session["_saml2_subject_id"] = code(subject_id)


def _get_subject_id(session):
    try:
        return decode(session["_saml2_subject_id"])
    except KeyError:
        return None


def _get_location(http_info):
    try:
        headers = dict(http_info["headers"])
        return headers["Location"]
    except KeyError:
        return http_info["url"]


@login_required
def welcome(r):
    try:
        return render(r, "django_SAML2_GLOBAL_CONFIG/welcome.html", {"user": r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(get_default_next_url())


def denied(r):
    return render(r, "django_SAML2_GLOBAL_CONFIG/denied.html")


def _create_new_user(user_identity):
    attributes_map = settings.SAML2_GLOBAL_CONFIG.get("ATTRIBUTES_MAP", {})
    user_name = user_identity[attributes_map.get("username", "UserName")][0]
    user = user_model.objects.create_user(user_name)
    for (user_attr, saml_attr) in attributes_map.items():
        if user_attr != "username":
            values = user_identity.get(saml_attr)
            if values is not None:
                setattr(user, user_attr, values[0])

    groups = [
        Group.objects.get(name=x)
        for x in settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get("USER_GROUPS", [])
    ]
    if parse_version(get_version()) >= parse_version("2.0"):
        user.groups.set(groups)
    else:
        user.groups = groups
    user.is_active = settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get(
        "ACTIVE_STATUS", True
    )
    user.is_staff = settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get(
        "STAFF_STATUS", True
    )
    user.is_superuser = settings.SAML2_GLOBAL_CONFIG.get("NEW_USER_PROFILE", {}).get(
        "SUPERUSER_STATUS", False
    )
    if settings.SAML2_GLOBAL_CONFIG.get("TRIGGER", {}).get("NEW_USER", None):
        import_string(settings.SAML2_GLOBAL_CONFIG["TRIGGER"]["NEW_USER"])(user, user_identity)
    user.save()
    return user


@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r))
    resp = r.POST.get("SAMLResponse", None)
    next_url = r.session.get("login_next_url", get_default_next_url())

    if not resp:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_SAML2_GLOBAL_CONFIG:denied"])
        )

    # Parsing the response throws `StatusAuthnFailed` exception on user related
    # authentication errors (such as user canceling the authentication), so
    # deny access if that happens.
    try:
        authn_response = saml_client.parse_authn_request_response(
            resp, entity.BINDING_HTTP_POST,
        )
    except StatusAuthnFailed:
        authn_response = None

    if authn_response is None:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_SAML2_GLOBAL_CONFIG:denied"])
        )

    session_info = authn_response.session_info()
    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_SAML2_GLOBAL_CONFIG:denied"])
        )

    user_name = user_identity[
        settings.SAML2_GLOBAL_CONFIG.get("ATTRIBUTES_MAP", {}).get("username", "UserName")
    ][0]

    target_user = None
    is_new_user = False

    find_user_spec = settings.SAML2_GLOBAL_CONFIG.get("TRIGGER", {}).get("FIND_USER")
    if find_user_spec:
        find_user = import_string(find_user_spec)
        target_user = find_user(user_identity)
    else:
        target_user = user_model.objects.filter(username=user_name).first()

    if target_user:
        if settings.SAML2_GLOBAL_CONFIG.get("TRIGGER", {}).get("BEFORE_LOGIN", None):
            import_string(settings.SAML2_GLOBAL_CONFIG["TRIGGER"]["BEFORE_LOGIN"])(
                target_user, user_identity
            )
    else:
        target_user = _create_new_user(user_identity)
        if settings.SAML2_GLOBAL_CONFIG.get("TRIGGER", {}).get("CREATE_USER", None):
            import_string(settings.SAML2_GLOBAL_CONFIG["TRIGGER"]["CREATE_USER"])(
                target_user, user_identity
            )
        is_new_user = True

    r.session.flush()
    _set_subject_id(r.session, session_info["name_id"])

    if target_user.is_active:
        target_user.backend = "django.contrib.auth.backends.ModelBackend"
        login(r, target_user)
    else:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_SAML2_GLOBAL_CONFIG:denied"])
        )

    if is_new_user:
        try:
            return render(r, "django_SAML2_GLOBAL_CONFIG/welcome.html", {"user": r.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


def signin(r):
    next_url = r.GET.get("next", get_default_next_url())

    try:
        if "next=" in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)[
                "next"
            ][0]
    except:
        next_url = r.GET.get("next", get_default_next_url())

    # Only permit signin requests where the next_url is a safe URL
    if not is_safe_url(next_url, None):
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_SAML2_GLOBAL_CONFIG:denied"])
        )

    r.session["login_next_url"] = next_url

    idp_entity_id = None
    try:
        idp_entity_id = settings.SAML2_GLOBAL_CONFIG["SAML_CLIENT_SETTINGS"]["service"]["sp"][
            "idp"
        ]
    except KeyError:
        pass

    relay_state = ""
    try:
        relay_state = settings.SAML2_GLOBAL_CONFIG["SAML_CLIENT_SETTINGS"]["service"]["sp"][
            "relay_state"
        ]
    except KeyError:
        pass

    binding = (
        settings.SAML2_GLOBAL_CONFIG.get("SAML_CLIENT_SETTINGS", {})
        .get("service", {})
        .get("sp", {})
        .get("binding", BINDING_HTTP_REDIRECT)
    )

    saml_client = _get_saml_client(get_current_domain(r))
    _, info = saml_client.prepare_for_authenticate(
        idp_entity_id, relay_state=relay_state, binding=binding
    )

    if binding == BINDING_HTTP_REDIRECT:
        redirect_url = None
        for key, value in info["headers"]:
            if key == "Location":
                redirect_url = value
                break
        return HttpResponseRedirect(redirect_url)

    elif binding == BINDING_HTTP_POST:
        return HttpResponse(info["data"])

    else:
        return HttpResponseServerError("Sso binding not supported")


def signout(r):
    """
    Initiates saml2 logout.

    :param r: HTTP request
    """
    binding = (
        settings.SAML2_GLOBAL_CONFIG.get("SAML_CLIENT_SETTINGS", {})
        .get("service", {})
        .get("sp", {})
        .get("binding", BINDING_HTTP_REDIRECT)
    )
    saml_client = _get_saml_client(get_current_domain(r))
    subject_id = _get_subject_id(r.session)
    idp_entity_id = None
    try:
        idp_entity_id = settings.SAML2_GLOBAL_CONFIG["SAML_CLIENT_SETTINGS"]["service"]["sp"][
            "idp"
        ]
    except KeyError:
        return HttpResponseServerError("Idp not defined")

    response = saml_client.do_logout(
        subject_id, [idp_entity_id], "", None, expected_binding=binding
    )
    return handle_logout_response(response)


def handle_logout_response(response):
    """
    Handles saml2 logout response.

    :param response: Saml2 logout response
    """
    if len(response) > 1:
        # Currently only one source is supported
        return HttpResponseServerError("Logout from several sources not supported")
    for entityid, logout_info in response.items():
        if isinstance(logout_info, tuple):
            # logout_info is a tuple containing header information and a HTML message.
            binding, http_info = logout_info
            if binding == BINDING_HTTP_POST:
                # Display content defined in logout response
                body = "".join(http_info["data"])
                return HttpResponse(body)
            elif binding == BINDING_HTTP_REDIRECT:
                # Redirect to address defined in logout response
                return HttpResponseRedirect(_get_location(http_info))
            else:
                # Unknown binding
                return HttpResponseServerError("Logout binding not supported")
        else:  # result from logout, should be OK
            pass

    return HttpResponseServerError("Failed to log out")


def finish_signout(r):
    """
    Logout local user

    :param r: HTTP request
    """
    logout(r)
    return render(r, "django_SAML2_GLOBAL_CONFIG/signout.html")
