from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from common.serializers.fields import EncryptedField

__all__ = ['CertSettingSerializer']


class CertSettingSerializer(serializers.Serializer):
    PREFIX_TITLE = _('Certificate')

    AUTH_CERT = serializers.BooleanField(
        default=False, label=_('Certificate')
    )
    AUTH_CERT_ENROLL_ENABLED = serializers.BooleanField(
        default=False, label=_('Enrollment'),
        help_text=_('Whether to enable user certificate enrollment')
    )
    AUTH_CERT_ENROLL_VALIDITY_DAYS = serializers.IntegerField(
        default=365, label=_('Enrollment Validity Days'),
        help_text=_('Validity period (days) for issued certificates')
    )
    AUTH_CERT_CHALLENGE_TTL = serializers.IntegerField(
        default=300, label=_('Challenge TTL (seconds)'),
        help_text=_('Time-to-live (seconds) for authentication challenge codes')
    )
    AUTH_CERT_DEFAULT_PIN = EncryptedField(
        default='', allow_blank=True, label=_('USB-Key Default PIN'),
        help_text=_('Default USB Key PIN used for administrator reset')
    )
