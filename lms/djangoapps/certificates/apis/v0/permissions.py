"""
This module provides a custom DRF Permission class for supporting the course certificates
to Admin users and users whom they belongs to.
"""

from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.permissions import IsAdminUser

from openedx.core.djangoapps.user_api.accounts.serializers import get_profile_visibility


class IsOwnerOrPublicProfile(IsAdminUser):
    """
    Method that will ensure whether the requesting user is staff or
    the user whom the certificate belongs to
    """
    def has_permission(self, request, view):
        requested_profile_username = view.kwargs.get('username')
        is_staff = super(IsOwnerOrPublicProfile, self).has_permission(request, view)
        is_owner = request.user.username == requested_profile_username

        if any([is_staff, is_owner]):
            return True

        user = User.objects.get(username=requested_profile_username)
        configuration = settings.ACCOUNT_VISIBILITY_CONFIGURATION

        account_privacy = get_profile_visibility(user.profile, user, configuration)
        return account_privacy == 'all_users'
