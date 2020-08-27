from uuid import uuid4

from django.db import models
from django.conf import settings
from django.apps import apps

from django.utils.translation import ugettext_lazy as _
from django.utils import timezone


STATUSES = (
    ("enabled", "Enabled"),
    ("disabled", "Disabled"),
)


class Configuration(models.Model):
    uuid = models.UUIDField(_('UUID'), primary_key=True, default=uuid4, editable=False)
    name = models.TextField(_('name'))

    idp_sso_url = models.TextField(_('idp sso url'), null=True, blank=False)
    idp_slo_url = models.TextField(_('idp slo url'), null=True, blank=False)
    idp_certificate = models.TextField(_('idp certificate'), null=True, blank=False)

    provision_users = models.BooleanField(_('provision users'), default=False)

    notify_existing_users_on_enable = models.BooleanField(_('notify existing users on enable'), default=False)

    status = models.TextField(_('status'), choices=STATUSES, default='disabled')
    status_at = models.DateTimeField(_('status at'), default=timezone.now)

    saas_entity = models.ForeignKey(
        settings.SAML2_GLOBAL_CONFIG.get('SAAS_ENTITY_MODEL'),
        on_delete=models.PROTECT,
        related_name='sso_configurations')
