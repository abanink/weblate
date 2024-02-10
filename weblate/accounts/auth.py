# Copyright © Michal Čihař <michal@weblate.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from django.conf import settings
from django.contrib.auth.backends import ModelBackend, RemoteUserBackend
from django.db.models.signals import pre_save
from django.dispatch.dispatcher import receiver

from weblate.auth.models import User

from weblate.logger import LOGGER
from weblate.utils.requests import request as weblate_request

def try_get_user(username, list_all=False):
    """Wrapper to get User object for authentication."""
    method = User.objects.filter if list_all else User.objects.get
    if "@" in username:
        return method(email=username)
    return method(username=username)


class WeblateUserBackend(ModelBackend):
    """Weblate authentication backend."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Prohibit login for anonymous user and allows to login by e-mail."""
        if username == settings.ANONYMOUS_USER_NAME or username is None:
            return None

        try:
            user = try_get_user(username)
            if user.check_password(password):
                return user
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            pass
        return None

    def get_user(self, user_id):
        try:
            user = User.objects.select_related("profile").get(pk=user_id)
        except User.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None


@receiver(pre_save, sender=User)
def disable_anon_user_password_save(sender, instance, **kwargs):
    """Block setting password for anonymous user."""
    if instance.is_anonymous and instance.has_usable_password():
        raise ValueError("Anonymous user can not have usable password!")

# Note: to activate the OpenWebAuth Backend, the administrator must add this to weblate/settings.py:
#AUTHENTICATION_BACKENDS = (
#    ...
#    "weblate.accounts.auth.OpenWebAuthBackend",
#)

# https://docs.djangoproject.com/en/5.0/ref/contrib/auth/#django.contrib.auth.backends.RemoteUserBackend
class OpenWebAuthBackend(RemoteUserBackend):
    def configure_user(self, request, user, created):
        LOGGER.info(f"OpenWebAuthBackend.configure_user called for user {user}")

        # disabled for testing; before releasing, re-activate this
        #if not created:
        #    LOGGER.info("User existed before - skipping")
        #    return user
        
        # if the user was created, set minimal info like a usable (but unknown) password and email address (fetched as OpenWebAuth client)
        LOGGER.info(f"Configuring new user now, username = {user.username}")
        
        server_domain = settings.SITE_DOMAIN
        user_domain = user.username.rpartition('@')[2]
        if user_domain is None:
            LOGGER.debug(f"Cannot determine domain from username {user.username}")
            return user
       
        # for email fetching: request on the remote user's domain for /userinfo?zid=sys@<this server domain>&rel=email with Accept-Content = application/json
        # sys@ prefix for our site actor handle because remote software expects a handle like me@example.com, and takes the part after @ as the domain
        #
        # The remote domain should answer with the email address in JSON format if the user approved sharing his email address
        # {
        #    "email": "<user's email address"
        #}
        request_url = f"https://{user_domain}/userinfo?zid=sys@{server_domain}&rel=email"
        LOGGER.info(f"Request url = {request_url}")
        user_info_response = weblate_request("get", request_url)
        
        LOGGER.info(f"Response from remote server: {user_info_response}") 

        # TODO fetch email address from response and configure it for this user

        return user
    
