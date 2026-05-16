from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from datetime import timedelta
from django.conf import settings


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        expiry_hours = getattr(settings, 'TOKEN_EXPIRY_HOURS', 24)
        if token.created < timezone.now() - timedelta(hours=expiry_hours):
            token.delete()
            raise AuthenticationFailed('Token negalioja. Prisijunkite iš naujo.')
        return user, token
