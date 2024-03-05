# Copyright © Michal Čihař <michal@weblate.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import io
import os
import random
import re
import string
import time
from collections import defaultdict
from datetime import datetime, timedelta
from importlib import import_module
from urllib.parse import urlparse, urlunparse

import social_django.utils
from asgiref.sync import async_to_sync
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.core.cache import InvalidCacheBackendError, caches
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.core.mail.message import EmailMultiAlternatives
from django.core.signing import (
    BadSignature,
    SignatureExpired,
    TimestampSigner,
    dumps,
    loads,
)
from django.db import transaction
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseServerError
from django.middleware.csrf import rotate_token
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.cache import patch_response_headers
from django.utils.decorators import method_decorator
from django.utils.http import urlencode
from django.utils.translation import gettext
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.views.generic import ListView, TemplateView, UpdateView
from PIL import Image
from requests.exceptions import JSONDecodeError
from rest_framework.authtoken.models import Token
from social_core.actions import do_auth
from social_core.backends.open_id import OpenIdAuth
from social_core.exceptions import (
    AuthAlreadyAssociated,
    AuthCanceled,
    AuthFailed,
    AuthForbidden,
    AuthMissingParameter,
    AuthStateForbidden,
    AuthStateMissing,
    InvalidEmail,
    MissingBackend,
)
from social_django.utils import load_backend, load_strategy
from social_django.views import complete, disconnect

from weblate.accounts.avatar import (
    get_avatar_cache_key,
    get_avatar_image,
    get_fallback_avatar_url,
)
from weblate.accounts.forms import (
    CaptchaForm,
    CommitForm,
    ContactForm,
    DashboardSettingsForm,
    EmailForm,
    EmptyConfirmForm,
    GroupAddForm,
    GroupRemoveForm,
    LanguagesForm,
    LoginForm,
    NotificationForm,
    PasswordConfirmForm,
    ProfileForm,
    RegistrationForm,
    ResetForm,
    SetPasswordForm,
    SubscriptionForm,
    UserForm,
    UserSearchForm,
    UserSettingsForm,
)
from weblate.accounts.models import AuditLog, Subscription, VerifiedEmail
from weblate.accounts.notifications import (
    FREQ_INSTANT,
    FREQ_NONE,
    NOTIFICATIONS,
    SCOPE_ADMIN,
    SCOPE_ALL,
    SCOPE_COMPONENT,
    SCOPE_PROJECT,
    SCOPE_WATCHED,
    send_notification_email,
)
from weblate.accounts.pipeline import EmailAlreadyAssociated, UsernameAlreadyAssociated
from weblate.accounts.utils import remove_user
from weblate.auth.forms import UserEditForm
from weblate.auth.models import Invitation, OwaVerification, User, get_auth_keys
from weblate.auth.utils import format_address
from weblate.logger import LOGGER
from weblate.trans.models import Change, Component, Project, Suggestion, Translation
from weblate.trans.models.component import translation_prefetch_tasks
from weblate.trans.models.project import prefetch_project_flags
from weblate.trans.util import redirect_next
from weblate.utils import messages
from weblate.utils.errors import add_breadcrumb, report_error
from weblate.utils.ratelimit import check_rate_limit, session_ratelimit_post
from weblate.utils.request import get_ip_address, get_user_agent
from weblate.utils.requests import request as weblate_request
from weblate.utils.stats import prefetch_stats
from weblate.utils.token import get_token
from weblate.utils.views import get_paginator, parse_path

CONTACT_TEMPLATE = """
Message from %(name)s <%(email)s>:

%(message)s
"""


MESSAGE_TEMPLATE = """
{message}

--
User: {username}
IP address: {address}
User agent: {agent}
"""

CONTACT_SUBJECTS = {
    "lang": "New language request",
    "reg": "Registration problems",
    "hosting": "Commercial hosting",
    "account": "Suspicious account activity",
    "trial": "Trial extension request",
}

ANCHOR_RE = re.compile(r"^#[a-z]+$")

NOTIFICATION_PREFIX_TEMPLATE = "notifications__{}"

ALLOWED_SIZES = (
    # Used in top navigation
    24,
    # In text avatars
    32,
    # 80 pixels used when linked with weblate.org
    80,
    # Public profile
    128,
)


class EmailSentView(TemplateView):
    r"""Class for rendering "E-mail sent" page."""

    template_name = "accounts/email-sent.html"

    def get_context_data(self, **kwargs):
        """Create context for rendering page."""
        context = super().get_context_data(**kwargs)
        context["validity"] = settings.AUTH_TOKEN_VALID // 3600
        context["is_reset"] = False
        context["is_remove"] = False
        if self.request.flags["password_reset"]:
            context["title"] = gettext("Password reset")
            context["is_reset"] = True
        elif self.request.flags["account_remove"]:
            context["title"] = gettext("Remove account")
            context["is_remove"] = True
        else:
            context["title"] = gettext("User registration")

        return context

    def get(self, request, *args, **kwargs):
        if not request.session.get("registration-email-sent"):
            return redirect("home")

        request.flags = {
            "password_reset": request.session["password_reset"],
            "account_remove": request.session["account_remove"],
        }

        # Remove session for not authenticated user here.
        # It is no longer needed and will just cause problems
        # with multiple registrations from single browser.
        if not request.user.is_authenticated:
            request.session.flush()
        else:
            request.session.pop("registration-email-sent")

        return super().get(request, *args, **kwargs)


def mail_admins_contact(request, subject, message, context, sender, to):
    """Send a message to the admins, as defined by the ADMINS setting."""
    LOGGER.info("contact form from %s", sender)
    if not to and settings.ADMINS:
        to = [a[1] for a in settings.ADMINS]
    elif not settings.ADMINS:
        messages.error(request, gettext("Could not send message to administrator."))
        LOGGER.error("ADMINS not configured, cannot send message")
        return

    if settings.CONTACT_FORM == "reply-to":
        kwargs = {"headers": {"Reply-To": sender}}
    else:
        kwargs = {"from_email": sender}

    mail = EmailMultiAlternatives(
        subject=f"{settings.EMAIL_SUBJECT_PREFIX}{subject % context}",
        body=MESSAGE_TEMPLATE.format(
            message=message % context,
            address=get_ip_address(request),
            agent=get_user_agent(request),
            username=request.user.username,
        ),
        to=to,
        **kwargs,
    )

    mail.send(fail_silently=False)

    messages.success(
        request, gettext("Your request has been sent, you will shortly hear from us.")
    )


def redirect_profile(page=""):
    url = reverse("profile")
    if page and ANCHOR_RE.match(page):
        url = url + page
    return HttpResponseRedirect(url)


def get_notification_forms(request):
    user = request.user
    subscriptions = defaultdict(dict)
    initials = {}

    # Ensure watched, admin and all scopes are visible
    for needed in (SCOPE_WATCHED, SCOPE_ADMIN, SCOPE_ALL):
        key = (needed, -1, -1)
        subscriptions[key] = {}
        initials[key] = {"scope": needed, "project": None, "component": None}
    active = (SCOPE_WATCHED, -1, -1)

    # Include additional scopes from request
    if "notify_project" in request.GET:
        try:
            project = user.allowed_projects.get(pk=request.GET["notify_project"])
            active = key = (SCOPE_PROJECT, project.pk, -1)
            subscriptions[key] = {}
            initials[key] = {
                "scope": SCOPE_PROJECT,
                "project": project,
                "component": None,
            }
        except (ObjectDoesNotExist, ValueError):
            pass
    if "notify_component" in request.GET:
        try:
            component = Component.objects.filter_access(user).get(
                pk=request.GET["notify_component"],
            )
            active = key = (SCOPE_COMPONENT, -1, component.pk)
            subscriptions[key] = {}
            initials[key] = {
                "scope": SCOPE_COMPONENT,
                "component": component,
            }
        except (ObjectDoesNotExist, ValueError):
            pass

    # Populate scopes from the database
    for subscription in user.subscription_set.select_related("project", "component"):
        key = (
            subscription.scope,
            subscription.project_id or -1,
            subscription.component_id or -1,
        )
        subscriptions[key][subscription.notification] = subscription.frequency
        initials[key] = {
            "scope": subscription.scope,
            "project": subscription.project,
            "component": subscription.component,
        }

    # Generate forms
    for i, details in enumerate(sorted(subscriptions.items())):
        yield NotificationForm(
            user=user,
            show_default=i > 1,
            removable=i > 2,
            subscriptions=details[1],
            is_active=details[0] == active,
            initial=initials[details[0]],
            prefix=NOTIFICATION_PREFIX_TEMPLATE.format(i),
            data=request.POST if request.method == "POST" else None,
        )
    for i in range(len(subscriptions), 200):
        prefix = NOTIFICATION_PREFIX_TEMPLATE.format(i)
        if prefix + "-scope" in request.POST or i < len(subscriptions):
            yield NotificationForm(
                user=user,
                show_default=i > 1,
                removable=i > 2,
                subscriptions={},
                is_active=i == 0,
                prefix=prefix,
                data=request.POST,
                initial=initials[details[0]],
            )


@never_cache
@login_required
def user_profile(request):
    user = request.user
    profile = user.profile
    profile.fixup_profile(request)

    form_classes = [
        LanguagesForm,
        SubscriptionForm,
        UserSettingsForm,
        DashboardSettingsForm,
        ProfileForm,
        CommitForm,
        UserForm,
    ]
    forms = [form.from_request(request) for form in form_classes]
    forms.extend(get_notification_forms(request))
    all_backends = get_auth_keys()

    if request.method == "POST":
        if all(form.is_valid() for form in forms):
            # Save changes
            for form in forms:
                if hasattr(form, "audit"):
                    form.audit(request)
                form.save()

            messages.success(request, gettext("Your profile has been updated."))

            # Redirect after saving (and possibly changing language)
            return redirect_profile(request.POST.get("activetab"))
    elif not user.has_usable_password() and "email" in all_backends:
        messages.warning(request, render_to_string("accounts/password-warning.html"))

    social = user.social_auth.all()
    social_names = [assoc.provider for assoc in social]
    new_backends = [
        x for x in sorted(all_backends) if x == "email" or x not in social_names
    ]
    user_translation_ids = set(
        Change.objects.filter(
            user=user, timestamp__gte=timezone.now() - timedelta(days=90)
        ).values_list("translation", flat=True)
    )
    license_components = (
        Component.objects.filter_access(user)
        .filter(translation__id__in=user_translation_ids)
        .exclude(license="")
        .prefetch(alerts=False)
        .distinct()
        .order_by("license")
    )

    return render(
        request,
        "accounts/profile.html",
        {
            "languagesform": forms[0],
            "subscriptionform": forms[1],
            "usersettingsform": forms[2],
            "dashboardsettingsform": forms[3],
            "profileform": forms[4],
            "commitform": forms[5],
            "userform": forms[6],
            "notification_forms": forms[7:],
            "all_forms": forms,
            "user_groups": user.groups.prefetch_related(
                "roles", "projects", "languages", "components"
            ),
            "profile": profile,
            "title": gettext("User profile"),
            "licenses": license_components,
            "associated": social,
            "new_backends": new_backends,
            "has_email_auth": "email" in all_backends,
            "auditlog": user.auditlog_set.order()[:20],
        },
    )


@login_required
@session_ratelimit_post("remove")
@never_cache
def user_remove(request):
    is_confirmation = "remove_confirm" in request.session
    if is_confirmation:
        if request.method == "POST":
            remove_user(request.user, request)
            rotate_token(request)
            logout(request)
            messages.success(request, gettext("Your account has been removed."))
            return redirect("home")
        confirm_form = EmptyConfirmForm(request)

    elif request.method == "POST":
        confirm_form = PasswordConfirmForm(request, request.POST)
        if confirm_form.is_valid():
            store_userid(request, remove=True)
            request.GET = {"email": request.user.email}
            AuditLog.objects.create(
                request.user, request, "removal-request", **request.GET
            )
            return social_complete(request, "email")
    else:
        confirm_form = PasswordConfirmForm(request)

    return render(
        request,
        "accounts/removal.html",
        {"confirm_form": confirm_form, "is_confirmation": is_confirmation},
    )


@session_ratelimit_post("confirm")
@never_cache
def confirm(request):
    details = request.session.get("reauthenticate")
    if not details:
        return redirect("home")

    if request.method == "POST":
        confirm_form = PasswordConfirmForm(
            request, request.POST, user=User.objects.get(pk=details["user_pk"])
        )
        if confirm_form.is_valid():
            request.session.pop("reauthenticate")
            request.session["reauthenticate_done"] = True
            return redirect("social:complete", backend=details["backend"])
    else:
        confirm_form = PasswordConfirmForm(request)

    context = {"confirm_form": confirm_form}
    context.update(details)

    return render(request, "accounts/confirm.html", context)


def get_initial_contact(request):
    """Fill in initial contact form fields from request."""
    initial = {}
    if request.user.is_authenticated:
        initial["name"] = request.user.full_name
        initial["email"] = request.user.email
    return initial


@never_cache
def contact(request):
    captcha = None
    show_captcha = settings.REGISTRATION_CAPTCHA and not request.user.is_authenticated

    if request.method == "POST":
        form = ContactForm(request.POST)
        if show_captcha:
            captcha = CaptchaForm(request, form, request.POST)
        if not check_rate_limit("message", request):
            messages.error(
                request, gettext("Too many messages sent, please try again later.")
            )
        elif (captcha is None or captcha.is_valid()) and form.is_valid():
            mail_admins_contact(
                request,
                "%(subject)s",
                CONTACT_TEMPLATE,
                form.cleaned_data,
                format_address(form.cleaned_data["name"], form.cleaned_data["email"]),
                settings.ADMINS_CONTACT,
            )
            return redirect("home")
    else:
        initial = get_initial_contact(request)
        if request.GET.get("t") in CONTACT_SUBJECTS:
            initial["subject"] = CONTACT_SUBJECTS[request.GET["t"]]
        form = ContactForm(initial=initial)
        if show_captcha:
            captcha = CaptchaForm(request)

    return render(
        request,
        "accounts/contact.html",
        {"form": form, "captcha_form": captcha, "title": gettext("Contact")},
    )


@login_required
@session_ratelimit_post("hosting")
@never_cache
def hosting(request):
    """Form for hosting request."""
    if not settings.OFFER_HOSTING:
        return redirect("home")

    from weblate.billing.models import Billing

    billings = (
        Billing.objects.for_user(request.user)
        .filter(state=Billing.STATE_TRIAL)
        .order_by("-payment", "expiry")
    )

    return render(
        request,
        "accounts/hosting.html",
        {
            "title": gettext("Hosting"),
            "billings": billings,
        },
    )


@login_required
@session_ratelimit_post("trial")
@never_cache
def trial(request):
    """Form for hosting request."""
    if not settings.OFFER_HOSTING:
        return redirect("home")

    plan = request.POST.get("plan", "enterprise")

    # Avoid frequent requests for a trial for same user
    if plan != "libre" and request.user.auditlog_set.filter(activity="trial").exists():
        messages.error(
            request,
            gettext(
                "Seems you've already requested a trial period recently. "
                "Please contact us with your inquiry so we can find the "
                "best solution for you."
            ),
        )
        return redirect(reverse("contact") + "?t=trial")

    if request.method == "POST":
        from weblate.billing.models import Billing, Plan

        AuditLog.objects.create(request.user, request, "trial")
        billing = Billing.objects.create(
            plan=Plan.objects.get(slug=plan),
            state=Billing.STATE_TRIAL,
            expiry=timezone.now() + timedelta(days=14),
        )
        billing.owners.add(request.user)
        messages.info(
            request,
            gettext(
                "Your trial period is now up and running; "
                "create your translation project and start Weblating!"
            ),
        )
        return redirect(reverse("create-project") + f"?billing={billing.pk}")

    return render(request, "accounts/trial.html", {"title": gettext("Gratis trial")})


class UserPage(UpdateView):
    model = User
    template_name = "accounts/user.html"
    slug_field = "username"
    slug_url_kwarg = "user"
    context_object_name = "page_user"
    form_class = UserEditForm

    group_form = None

    def post(self, request, **kwargs):
        if not request.user.has_perm("user.edit"):
            raise PermissionDenied
        user = self.object = self.get_object()
        if "add_group" in request.POST:
            self.group_form = GroupAddForm(request.POST)
            if self.group_form.is_valid():
                user.groups.add(self.group_form.cleaned_data["add_group"])
                return HttpResponseRedirect(self.get_success_url() + "#groups")
        if "remove_group" in request.POST:
            form = GroupRemoveForm(request.POST)
            if form.is_valid():
                user.groups.remove(form.cleaned_data["remove_group"])
                return HttpResponseRedirect(self.get_success_url() + "#groups")
        if "remove_user" in request.POST:
            remove_user(user, request, skip_notify=True)
            return HttpResponseRedirect(self.get_success_url() + "#groups")

        return super().post(request, **kwargs)

    def form_valid(self, form):
        """If the form is valid, save the associated model."""
        self.object = form.save(self.request)
        return HttpResponseRedirect(self.get_success_url())

    def get_queryset(self):
        return super().get_queryset().select_related("profile")

    def get_context_data(self, **kwargs):
        """Create context for rendering page."""
        context = super().get_context_data(**kwargs)
        user = self.object
        request = self.request

        allowed_projects = request.user.allowed_projects

        # Filter all user activity
        all_changes = Change.objects.last_changes(request.user).filter(user=user)

        # Filter where project is active
        user_translation_ids = set(
            all_changes.content()
            .filter(timestamp__gte=timezone.now() - timedelta(days=90))
            .values_list("translation", flat=True)
        )
        user_translations = (
            Translation.objects.prefetch()
            .filter(
                id__in=list(user_translation_ids)[:10],
                component__project__in=allowed_projects,
            )
            .order()
        )

        context["page_profile"] = user.profile
        # Last user activity
        context["last_changes"] = all_changes.recent()
        context["last_changes_url"] = urlencode({"user": user.username})
        context["page_user_translations"] = translation_prefetch_tasks(
            prefetch_stats(user_translations)
        )
        owned = (user.owned_projects & allowed_projects.distinct()).order()[:11]
        context["page_owned_projects_more"] = len(owned) == 11
        context["page_owned_projects"] = prefetch_project_flags(
            prefetch_stats(owned[:10])
        )
        watched = (user.watched_projects & allowed_projects).order()[:11]
        context["page_watched_projects_more"] = len(watched) == 11
        context["page_watched_projects"] = prefetch_project_flags(
            prefetch_stats(watched[:10])
        )
        context["user_languages"] = user.profile.all_languages[:7]
        context["group_form"] = self.group_form or GroupAddForm()
        context["page_user_groups"] = (
            user.groups.annotate(Count("user"))
            .prefetch_related("defining_project")
            .order()
        )
        return context


def user_contributions(request, user: str):
    page_user = get_object_or_404(User, username=user)
    user_translation_ids = set(
        Change.objects.content()
        .filter(user=page_user)
        .values_list("translation", flat=True)
    )
    user_translations = (
        Translation.objects.filter_access(request.user)
        .prefetch()
        .filter(
            id__in=user_translation_ids,
        )
        .order()
    )
    return render(
        request,
        "accounts/user_contributions.html",
        {
            "page_user": page_user,
            "page_profile": page_user.profile,
            "page_user_translations": translation_prefetch_tasks(
                prefetch_stats(get_paginator(request, user_translations))
            ),
        },
    )


def user_avatar(request, user: str, size: int):
    """User avatar view."""
    if size not in ALLOWED_SIZES:
        raise Http404(f"Not supported size: {size}")

    avatar_user = get_object_or_404(User, username=user)

    if avatar_user.email == "noreply@weblate.org":
        return redirect(get_fallback_avatar_url(size))
    if avatar_user.email == f"noreply+{avatar_user.pk}@weblate.org":
        return redirect(os.path.join(settings.STATIC_URL, "state/ghost.svg"))

    response = HttpResponse(
        content_type="image/png", content=get_avatar_image(avatar_user, size)
    )

    patch_response_headers(response, 3600 * 24 * 7)

    return response


def redirect_single(request, backend):
    """Redirect user to single authentication backend."""
    return render(
        request,
        "accounts/redirect.html",
        {"backend": backend, "next": request.GET.get("next")},
    )


class WeblateLoginView(LoginView):
    """Login handler, just a wrapper around standard Django login."""

    form_class = LoginForm
    template_name = "accounts/login.html"
    redirect_authenticated_user = True

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        auth_backends = get_auth_keys()
        context["login_backends"] = [x for x in sorted(auth_backends) if x != "email"]
        context["can_reset"] = "email" in auth_backends
        context["title"] = gettext("Sign in")
        return context

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # Redirect signed in users to profile
        if request.user.is_authenticated:
            return redirect_profile()

        # Redirect if there is only one backend
        auth_backends = get_auth_keys()
        if len(auth_backends) == 1 and "email" not in auth_backends:
            return redirect_single(request, auth_backends.pop())

        return super().dispatch(request, *args, **kwargs)

    def form_invalid(self, form):
        rotate_token(self.request)
        return super().form_invalid(form)


class WeblateLogoutView(LogoutView):
    """Logout handler, just a wrapper around standard Django logout."""

    next_page = "home"

    @method_decorator(require_POST)
    @method_decorator(login_required)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        messages.info(self.request, gettext("Thank you for using Weblate."))
        return super().dispatch(request, *args, **kwargs)


def fake_email_sent(request, reset=False):
    """Fake redirect to e-mail sent page."""
    request.session["registration-email-sent"] = True
    request.session["password_reset"] = reset
    request.session["account_remove"] = False
    return redirect("email-sent")


@never_cache
def register(request):
    """Registration form."""
    captcha = None

    # Fetch invitation
    invitation = None
    initial = {}
    if invitation_pk := request.session.get("invitation_link"):
        try:
            invitation = Invitation.objects.get(pk=invitation_pk)
        except Invitation.DoesNotExist:
            del request.session["invitation_link"]
        else:
            initial["email"] = invitation.email

    # Allow registration at all?
    registration_open = settings.REGISTRATION_OPEN or bool(invitation)

    # Get list of allowed backends
    backends = get_auth_keys()
    if settings.REGISTRATION_ALLOW_BACKENDS and not invitation:
        backends = backends & set(settings.REGISTRATION_ALLOW_BACKENDS)
    elif not registration_open:
        backends = set()

    if request.method == "POST" and "email" in backends:
        form = RegistrationForm(request, request.POST)
        if settings.REGISTRATION_CAPTCHA:
            captcha = CaptchaForm(request, form, request.POST)
        if (captcha is None or captcha.is_valid()) and form.is_valid():
            if captcha:
                captcha.cleanup_session(request)
            if form.cleaned_data["email_user"]:
                AuditLog.objects.create(
                    form.cleaned_data["email_user"], request, "connect"
                )
                return fake_email_sent(request)
            store_userid(request)
            return social_complete(request, "email")
    else:
        form = RegistrationForm(request, initial=initial)
        if settings.REGISTRATION_CAPTCHA:
            captcha = CaptchaForm(request)

    # Redirect if there is only one backend
    if len(backends) == 1 and "email" not in backends and not invitation:
        return redirect_single(request, backends.pop())

    return render(
        request,
        "accounts/register.html",
        {
            "registration_email": "email" in backends,
            "registration_backends": backends - {"email"},
            "title": gettext("User registration"),
            "form": form,
            "captcha_form": captcha,
            "invitation": invitation,
        },
    )


@login_required
@never_cache
def email_login(request):
    """Connect e-mail."""
    captcha = None

    if request.method == "POST":
        form = EmailForm(request.POST)
        if settings.REGISTRATION_CAPTCHA:
            captcha = CaptchaForm(request, form, request.POST)
        if (captcha is None or captcha.is_valid()) and form.is_valid():
            if captcha:
                captcha.cleanup_session(request)
            email_user = form.cleaned_data["email_user"]
            if email_user and email_user != request.user:
                AuditLog.objects.create(
                    form.cleaned_data["email_user"], request, "connect"
                )
                return fake_email_sent(request)
            store_userid(request)
            return social_complete(request, "email")
    else:
        form = EmailForm()
        if settings.REGISTRATION_CAPTCHA:
            captcha = CaptchaForm(request)

    return render(
        request,
        "accounts/email.html",
        {"title": gettext("Register e-mail"), "form": form, "captcha_form": captcha},
    )


@login_required
@session_ratelimit_post("password")
@never_cache
def password(request):
    """Password change / set form."""
    do_change = True
    change_form = None
    usable = request.user.has_usable_password()

    if "email" not in get_auth_keys() and not usable:
        messages.error(
            request,
            gettext("Cannot reset password, e-mail authentication is turned off."),
        )
        return redirect("profile")

    if usable:
        if request.method == "POST":
            change_form = PasswordConfirmForm(request, request.POST)
            do_change = change_form.is_valid()
        else:
            change_form = PasswordConfirmForm(request)
            do_change = False

    if request.method == "POST":
        form = SetPasswordForm(request.user, request.POST)
        if form.is_valid() and do_change:
            # Clear flag forcing user to set password
            redirect_page = "#account"
            if "show_set_password" in request.session:
                del request.session["show_set_password"]
                redirect_page = ""

            # Change the password
            form.save(request)

            return redirect_profile(redirect_page)
    else:
        form = SetPasswordForm(request.user)

    return render(
        request,
        "accounts/password.html",
        {"title": gettext("Change password"), "change_form": change_form, "form": form},
    )


def reset_password_set(request):
    """Perform actual password reset."""
    user = User.objects.get(pk=request.session["perform_reset"])
    if user.has_usable_password():
        request.session.flush()
        request.session.set_expiry(None)
        messages.error(request, gettext("Password reset has been already completed."))
        return redirect("login")
    if request.method == "POST":
        form = SetPasswordForm(user, request.POST)
        if form.is_valid():
            request.session.set_expiry(None)
            form.save(request, delete_session=True)
            return redirect("login")
    else:
        form = SetPasswordForm(user)
    return render(
        request,
        "accounts/reset.html",
        {
            "title": gettext("Password reset"),
            "form": form,
            "captcha_form": None,
            "second_stage": True,
        },
    )


def get_registration_hint(email: str) -> str | None:
    domain = email.rsplit("@", 1)[-1]
    return settings.REGISTRATION_HINTS.get(domain)


@never_cache
def reset_password(request):
    """Password reset handling."""
    if request.user.is_authenticated:
        return redirect_profile()
    if "email" not in get_auth_keys():
        messages.error(
            request,
            gettext("Cannot reset password, e-mail authentication is turned off."),
        )
        return redirect("login")

    captcha = None

    # We're already in the reset phase
    if "perform_reset" in request.session:
        return reset_password_set(request)
    if request.method == "POST":
        form = ResetForm(request.POST)
        if settings.REGISTRATION_CAPTCHA:
            captcha = CaptchaForm(request, form, request.POST)
        if (captcha is None or captcha.is_valid()) and form.is_valid():
            if captcha:
                captcha.cleanup_session(request)
            if form.cleaned_data["email_user"]:
                audit = AuditLog.objects.create(
                    form.cleaned_data["email_user"], request, "reset-request"
                )
                if not audit.check_rate_limit(request):
                    store_userid(request, reset=True)
                    return social_complete(request, "email")
            else:
                email = form.cleaned_data["email"]
                send_notification_email(
                    None,
                    [email],
                    "reset-nonexisting",
                    context={
                        "address": get_ip_address(request),
                        "user_agent:": get_user_agent(request),
                        "registration_hint": get_registration_hint(email),
                    },
                )
            return fake_email_sent(request, True)
    else:
        form = ResetForm()
        if settings.REGISTRATION_CAPTCHA:
            captcha = CaptchaForm(request)

    return render(
        request,
        "accounts/reset.html",
        {
            "title": gettext("Password reset"),
            "form": form,
            "captcha_form": captcha,
            "second_stage": False,
        },
    )


@require_POST
@login_required
@session_ratelimit_post("reset_api")
def reset_api_key(request):
    """Reset user API key."""
    # Need to delete old token as key is primary key
    with transaction.atomic():
        Token.objects.filter(user=request.user).delete()
        Token.objects.create(user=request.user, key=get_token("wlu"))

    return redirect_profile("#api")


@require_POST
@login_required
@session_ratelimit_post("userdata")
def userdata(request):
    response = JsonResponse(request.user.profile.dump_data())
    response["Content-Disposition"] = 'attachment; filename="weblate.json"'
    return response


@require_POST
@login_required
def watch(request, path):
    user = request.user
    redirect_obj = obj = parse_path(request, path, (Component, Project))
    if isinstance(obj, Component):
        project = obj.project

        # Mute project level subscriptions
        mute_real(user, scope=SCOPE_PROJECT, component=None, project=project)
        # Manually enable component level subscriptions
        for default_subscription in user.subscription_set.filter(scope=SCOPE_WATCHED):
            subscription, created = user.subscription_set.get_or_create(
                notification=default_subscription.notification,
                scope=SCOPE_COMPONENT,
                component=obj,
                project=None,
                defaults={"frequency": default_subscription.frequency},
            )
            if not created and subscription.frequency != default_subscription.frequency:
                subscription.frequency = default_subscription.frequency
                subscription.save(update_fields=["frequency"])

        # Watch project
        obj = project
    user.profile.watched.add(obj)
    return redirect_next(request.GET.get("next"), redirect_obj)


@require_POST
@login_required
def unwatch(request, path):
    obj = parse_path(request, path, (Project,))
    request.user.profile.watched.remove(obj)
    request.user.subscription_set.filter(
        Q(project=obj) | Q(component__project=obj)
    ).delete()
    return redirect_next(request.GET.get("next"), obj)


def mute_real(user, **kwargs):
    for notification_cls in NOTIFICATIONS:
        if notification_cls.ignore_watched:
            continue
        subscription = user.subscription_set.get_or_create(
            notification=notification_cls.get_name(),
            defaults={"frequency": FREQ_NONE},
            **kwargs,
        )[0]
        if subscription.frequency != FREQ_NONE:
            subscription.frequency = FREQ_NONE
            subscription.save(update_fields=["frequency"])


@require_POST
@login_required
def mute(request, path):
    obj = parse_path(request, path, (Component, Project))
    if isinstance(obj, Component):
        mute_real(request.user, scope=SCOPE_COMPONENT, component=obj, project=None)
        return redirect(
            "{}?notify_component={}#notifications".format(reverse("profile"), obj.pk)
        )
    mute_real(request.user, scope=SCOPE_PROJECT, component=None, project=obj)
    return redirect(
        "{}?notify_project={}#notifications".format(reverse("profile"), obj.pk)
    )


class SuggestionView(ListView):
    paginate_by = 25
    model = Suggestion

    def get_queryset(self):
        if self.kwargs["user"] == "-":
            user = None
        else:
            user = get_object_or_404(User, username=self.kwargs["user"])
        return (
            Suggestion.objects.filter_access(self.request.user)
            .filter(user=user)
            .order()
        )

    def get_context_data(self, *, object_list=None, **kwargs):
        result = super().get_context_data(object_list=object_list, **kwargs)
        if self.kwargs["user"] == "-":
            user = User.objects.get(username=settings.ANONYMOUS_USER_NAME)
        else:
            user = get_object_or_404(User, username=self.kwargs["user"])
        result["page_user"] = user
        result["page_profile"] = user.profile
        return result


def store_userid(request, *, reset: bool = False, remove: bool = False):
    """Store user ID in the session."""
    request.session["social_auth_user"] = request.user.pk
    request.session["password_reset"] = reset
    request.session["account_remove"] = remove


@require_POST
@login_required
def social_disconnect(request, backend, association_id=None):
    """
    Wrapper around social_django.views.disconnect.

    - Requires POST (to avoid CSRF on auth)
    - Blocks disconnecting last entry
    """
    # Block removal of last social auth
    if request.user.social_auth.count() <= 1:
        messages.error(request, gettext("Could not remove user identity"))
        return redirect_profile("#account")

    # Block removal of last verified email
    verified = VerifiedEmail.objects.filter(social__user=request.user).exclude(
        social__provider=backend, social_id=association_id
    )
    if not verified.exists():
        messages.error(
            request,
            gettext("Add another identity by confirming your e-mail address first."),
        )
        return redirect_profile("#account")

    return disconnect(request, backend, association_id)


@never_cache
@require_POST
def social_auth(request, backend):
    """
    Wrapper around social_django.views.auth.

    - Incorporates modified social_djang.utils.psa
    - Requires POST (to avoid CSRF on auth)
    - Stores current user in session (to avoid CSRF upon completion)
    - Stores session ID in the request URL if needed
    """
    # Fill in idp in case it is not provided
    if backend == "saml" and "idp" not in request.GET:
        request.GET = request.GET.copy()
        request.GET["idp"] = "weblate"
    store_userid(request)
    uri = reverse("social:complete", args=(backend,))
    request.social_strategy = load_strategy(request)
    try:
        request.backend = load_backend(request.social_strategy, backend, uri)
    except MissingBackend:
        raise Http404("Backend not found")
    # Store session ID for OpenID based auth. The session cookies will not be sent
    # on returning POST request due to SameSite cookie policy
    if isinstance(request.backend, OpenIdAuth):
        request.backend.redirect_uri += "?authid={}".format(
            dumps(
                (request.session.session_key, get_ip_address(request)),
                salt="weblate.authid",
            )
        )
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)


def auth_fail(request, message):
    messages.error(request, message)
    return redirect(reverse("login"))


def registration_fail(request, message):
    messages.error(request, gettext("Could not complete registration.") + " " + message)
    messages.info(
        request,
        gettext("Please check if you have already registered an account.")
        + " "
        + gettext(
            "You can also request a new password, if you have lost your credentials."
        ),
    )

    return redirect(reverse("login"))


def auth_redirect_token(request):
    return auth_fail(
        request,
        gettext(
            "Try registering again to verify your identity, "
            "the confirmation link probably expired."
        ),
    )


def auth_redirect_state(request):
    return auth_fail(
        request, gettext("Could not authenticate due to invalid session state.")
    )


def handle_missing_parameter(request, backend, error):
    if backend != "email" and error.parameter == "email":
        return auth_fail(
            request,
            gettext("Got no e-mail address from third party authentication service.")
            + " "
            + gettext("Please register using e-mail instead."),
        )
    if error.parameter in ("email", "user", "expires"):
        return auth_redirect_token(request)
    if error.parameter in ("state", "code"):
        return auth_redirect_state(request)
    if error.parameter == "disabled":
        return auth_fail(request, gettext("New registrations are turned off."))
    return None


@csrf_exempt
@never_cache
def social_complete(request, backend):  # noqa: C901
    """
    Wrapper around social_django.views.complete.

    - Handles backend errors gracefully
    - Intermediate page (autosubmitted by JavaScript) to avoid
      confirmations by bots
    - Restores session from authid for some backends (see social_auth)
    """
    if "authid" in request.GET:
        try:
            session_key, ip_address = loads(
                request.GET["authid"], max_age=600, salt="weblate.authid"
            )
        except (BadSignature, SignatureExpired):
            return auth_redirect_token(request)
        if ip_address != get_ip_address(request):
            return auth_redirect_token(request)
        engine = import_module(settings.SESSION_ENGINE)
        request.session = engine.SessionStore(session_key)

    if (
        "partial_token" in request.GET
        and "verification_code" in request.GET
        and "confirm" not in request.GET
    ):
        return render(
            request,
            "accounts/token.html",
            {
                "partial_token": request.GET["partial_token"],
                "verification_code": request.GET["verification_code"],
                "backend": backend,
            },
        )
    try:
        return complete(request, backend)
    except InvalidEmail:
        report_error()
        return auth_redirect_token(request)
    except AuthMissingParameter as error:
        report_error()
        result = handle_missing_parameter(request, backend, error)
        if result:
            return result
        raise
    except (AuthStateMissing, AuthStateForbidden):
        report_error()
        return auth_redirect_state(request)
    except AuthFailed:
        report_error()
        return auth_fail(
            request,
            gettext(
                "Could not authenticate, probably due to an expired token "
                "or connection error."
            ),
        )
    except AuthCanceled:
        report_error()
        return auth_fail(request, gettext("Authentication cancelled."))
    except AuthForbidden:
        report_error()
        return auth_fail(request, gettext("The server does not allow authentication."))
    except EmailAlreadyAssociated:
        return registration_fail(
            request,
            gettext(
                "The supplied e-mail address is already in use for another account."
            ),
        )
    except UsernameAlreadyAssociated:
        return registration_fail(
            request,
            gettext("The supplied username is already in use for another account."),
        )
    except AuthAlreadyAssociated:
        return registration_fail(
            request,
            gettext(
                "The supplied user identity is already in use for another account."
            ),
        )
    except ValidationError as error:
        report_error()
        return registration_fail(request, str(error))


@login_required
@require_POST
def subscribe(request):
    if "onetime" in request.POST:
        component = Component.objects.get(pk=request.POST["component"])
        request.user.check_access_component(component)
        subscription = Subscription(
            user=request.user,
            notification=request.POST["onetime"],
            scope=SCOPE_COMPONENT,
            frequency=FREQ_INSTANT,
            project=component.project,
            component=component,
            onetime=True,
        )
        try:
            subscription.full_clean()
            subscription.save()
        except ValidationError:
            pass
        messages.success(request, gettext("Notification settings adjusted."))
    return redirect_profile("#notifications")


def unsubscribe(request):
    if "i" in request.GET:
        signer = TimestampSigner()
        try:
            subscription = Subscription.objects.get(
                pk=int(signer.unsign(request.GET["i"], max_age=24 * 3600))
            )
            subscription.frequency = FREQ_NONE
            subscription.save(update_fields=["frequency"])
            messages.success(request, gettext("Notification settings adjusted."))
        except (BadSignature, SignatureExpired, Subscription.DoesNotExist):
            messages.error(
                request,
                gettext(
                    "The notification change link is no longer valid, "
                    "please sign in to configure notifications."
                ),
            )

    return redirect_profile("#notifications")


@csrf_exempt
@never_cache
def saml_metadata(request):
    if "social_core.backends.saml.SAMLAuth" not in settings.AUTHENTICATION_BACKENDS:
        raise Http404

    # Generate metadata
    complete_url = reverse("social:complete", args=("saml",))
    saml_backend = social_django.utils.load_backend(
        load_strategy(request), "saml", complete_url
    )
    metadata, errors = saml_backend.generate_metadata_xml()

    # Handle errors
    if errors:
        add_breadcrumb(category="auth", message="SAML errors", errors=errors)
        report_error(level="error", cause="SAML metadata")
        return HttpResponseServerError(content=", ".join(errors))

    return HttpResponse(content=metadata, content_type="text/xml")


class UserList(ListView):
    paginate_by = 50
    model = User
    form_class = UserSearchForm

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get_base_queryset(self):
        return User.objects.filter(is_active=True, is_bot=False)

    def get_queryset(self):
        users = self.get_base_queryset()
        form = self.form
        if form.is_valid():
            search = form.cleaned_data.get("q", "")
            if search:
                users = users.search(search, parser=form.fields["q"].parser)
        else:
            users = users.order()

        return users.order_by(self.sort_query)

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.form = form = self.form_class(request.GET)
        self.sort_query = None
        if form.is_valid():
            self.sort_query = form.cleaned_data.get("sort_by")
        if not self.sort_query:
            self.sort_query = "-date_joined"

    def get_context_data(self, **kwargs):
        """Create context for rendering page."""
        context = super().get_context_data(**kwargs)
        context["form"] = self.form
        context["sort_query"] = self.sort_query
        context["sort_name"] = self.form.sort_choices[self.sort_query.strip("-")]
        context["sort_choices"] = self.form.sort_choices
        context["search_items"] = (
            ("q", self.form.cleaned_data.get("q", "").strip()),
            ("sort_by", self.sort_query),
        )
        context["query_string"] = urlencode(context["search_items"])
        return context


@async_to_sync
async def owa_server(request):
    ret_response = {"success": "false"}
    LOGGER.info("Hit OWA endpoint")

    public_key = None
    avatar_link = None
    key_id = None
    remote_user_cache = caches["default"]

    def perform_webfinger(url, domain=None):
        if not domain:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

        webfinger_url = f"https://{domain}/.well-known/webfinger?resource={url}"
        LOGGER.info(
            f"Performing webfinger lookup for url {url} on domain {domain}, calling {webfinger_url}"
        )

        wf_response = weblate_request("get", webfinger_url)
        if wf_response.status_code != 200:
            LOGGER.info(
                f"Webfinger request failed, status code = {wf_response.status_code}"
            )
            return None

        try:
            wf_result = wf_response.json()
        except JSONDecodeError as e:
            LOGGER.debug(f"Json parse error: {e}")
            return None

        LOGGER.debug(f"Webfinger result = {wf_result}")
        return wf_result

    def webfinger_find_address(wf_result, check_routine=callable):
        subject = wf_result["subject"]
        if subject:
            subject = str(subject)
            if check_routine(subject):
                address = subject.removeprefix("acct:")
                LOGGER.debug(f"Address {address} found in subject")
                return address

        address = None
        aliases = wf_result["aliases"]
        if aliases and isinstance(aliases, list):
            for a in aliases:
                a = str(a)
                if check_routine(a):
                    address = a.removeprefix("acct:")
                    LOGGER.debug(f"Address {address} found in alias")
                    break

        return address

    # Check that a claimed address wil resolve to the keyId
    #
    # We will use the claimed address as username and in the key for caching the avatar
    # we need to make sure that this claimed address can be trusted
    # This can be done by looking up the keyId on the claimed address's domain
    # if it fails, someone is providing an invalid address to use as username
    def verify_address(address, key_id):
        domain = address.rpartition("@")[2]
        if not domain:
            return False

        wf_result = perform_webfinger(key_id, domain)
        return webfinger_find_address(wf_result, lambda address: address == key_id)

    def try_fetch_remote_user(key_id):
        wf_result = perform_webfinger(key_id)
        if not wf_result:
            LOGGER.debug(f"Webfinger failed for {key_id}")
            return None

        address = extract_address_from_webfinger(wf_result)
        verify_addr_result = verify_address(address, key_id)
        if not verify_addr_result:
            LOGGER.info(
                f"Address {address} could not be verified - this is a fatal error"
            )
            return None

        LOGGER.info(f"Address verification passed for {address}")
        return store_remote_user_in_cache(key_id, wf_result)

    def extract_publickey_from_webfinger(wf_result):
        # extract public key from webfinger result
        pubkey_property = "https://w3id.org/security/v1#publicKeyPem"
        # TODO also return None if the public key is not a valid format?
        wf_properties = wf_result["properties"]
        if not wf_properties or not wf_properties[pubkey_property]:
            LOGGER.info("Unable to retrieve public key from webfinger")

        public_key = wf_properties[pubkey_property]
        LOGGER.debug(f"Public key retrieved: {public_key}")
        return public_key

    def extract_address_from_webfinger(wf_result):
        # extract remote user address from webfinger
        # it could be in the subject or in the aliases

        address = webfinger_find_address(
            wf_result, lambda field: field.startswith("acct:")
        )

        if address is None:
            LOGGER.info("Unable to retrieve address from webfinger")
            return None

        LOGGER.debug(f"Found address {address} from webfinger")
        return address

    def extract_avatar_from_webfinger(wf_result):
        # read the avatar from the webfinger link http://webfinger.net/rel/avatar
        avatar_link = None
        links = wf_result["links"]
        if links and isinstance(links, list):
            for l in links:
                if l["rel"] == "http://webfinger.net/rel/avatar":
                    avatar_link = l["href"]
                    LOGGER.debug(
                        f"Found avatar link from webfinger response: {avatar_link}"
                    )
                    break
        return avatar_link

    def create_cache_key_from_remote_user(remote_user):
        return f"remote_user_{remote_user}"

    def store_remote_user_in_cache(key, wf_result):
        public_key = extract_publickey_from_webfinger(wf_result).encode()
        address = extract_address_from_webfinger(wf_result)
        avatar_link = extract_avatar_from_webfinger(wf_result)
        remote_user = {
            "pubkey": public_key,
            "address": address,
            "avatar_link": avatar_link,
        }
        remote_user_cache.set(create_cache_key_from_remote_user(key), remote_user)
        return remote_user

    def parse_sigheader(header):
        ret = {}

        m = re.search(r'keyId="(.*?)"', header)
        if m:
            ret["keyId"] = m.group(1)

        m = re.search(r"created=([0-9]*)", header)
        if m:
            ret["created"] = m.group(1)

        m = re.search(r"expires=([0-9]*)", header)
        if m:
            ret["expires"] = m.group(1)

        m = re.search(r'algorithm="(.*?)"', header)
        if m:
            ret["algorithm"] = m.group(1)

        m = re.search(r'headers="(.*?)"', header)
        if m:
            ret["headers"] = m.group(1).split()

        m = re.search(r'signature="(.*?)"', header)
        if m:
            ret["signature"] = base64.b64decode(m.group(1).strip())

        if ret.get("signature") and ret.get("algorithm") and (not ret.get("headers")):
            ret["headers"] = ["date"]

        LOGGER.info(f"parse_sigheader: returning {ret}")
        return ret

    def sig_verify(request, sig_block, pubkey):
        LOGGER.info("Verify signature now...")

        headers = {k.lower(): v for k, v in dict(request.headers).items()}
        LOGGER.debug(f"Prepared headers: {headers}")
        headers["(request-target)"] = (
            request.method.lower() + " " + request.get_full_path()
        )
        LOGGER.debug(f"headers = {headers}")

        if not sig_block:
            header_sig = request.headers["Signature"]
            header_auth = request.headers["Authorization"]

            if header_sig:
                sig_block = parse_sigheader(header_sig)
            elif header_auth:
                sig_block = parse_sigheader(header_auth)

            if not sig_block:
                LOGGER.info("No signature provided")
                return False

        signed_headers = sig_block["headers"]
        if not signed_headers:
            signed_headers = ["date"]

        LOGGER.info(f"Signed header: {signed_headers}")
        signed_data = ""
        for h in signed_headers:
            h_val = headers[h]
            LOGGER.debug(f"Checking header {h} = {h_val}")
            if h == "(created)":
                created_time = sig_block["(created)"]
                if not created_time or created_time > time.time():
                    LOGGER.info("Created time missing or in the future")
                    return False
                signed_data += h + ": " + created_time + "\n"
            elif h == "(expires)":
                expire_time = sig_block["(expires)"]
                if not expire_time or expire_time < time.time():
                    LOGGER.info("Expire time not present or passed")
                    return False
                signed_data += h + ": " + expire_time + "\n"
            elif h == "date":
                now = datetime.now()
                past = now - timedelta(days=1)
                future = now + timedelta(days=1)
                try:
                    curr = datetime.strptime(h_val, "%a, %d %b %Y %H:%M:%S GMT")
                    if curr > future or curr < past:
                        LOGGER.info("Bad time")
                        return False
                except OSError:
                    return False
            else:
                signed_data += h + ": " + h_val + "\n"

        # Strip end linefeed
        signed_data = signed_data.rstrip("\n").encode()
        LOGGER.debug(f"Signed data: {signed_data}")

        sig_algorithm = sig_block["algorithm"]
        if sig_algorithm == "rsa-sha256":
            alg = hashes.SHA256()
        elif sig_algorithm == "rsa-sha512":
            alg = hashes.SHA512()
        else:
            LOGGER.info(f"Unsupported algorithm ({sig_algorithm})")
            return False

        if not sig_block["keyId"]:
            return False

        try:
            LOGGER.info("Starting crypto verify now")
            pubkey.verify(sig_block["signature"], signed_data, padding.PKCS1v15(), alg)
        except InvalidSignature:
            LOGGER.info("Signature invalid")
            return False

        return True

    def store_avatar_image(image, size):
        resized_image = Image.open(io.BytesIO(image.content)).resize((size, size))
        imgByteArr = io.BytesIO()
        resized_image.save(imgByteArr, format="PNG")
        avatar_image = imgByteArr.getvalue()

        avatar_cache_key = get_avatar_cache_key(address, size)
        cache.set(avatar_cache_key, avatar_image)

        LOGGER.info(f"Stored avatar for size {size} in cache at key {avatar_cache_key}")

    def generate_token(length=32):
        # TODO this should be run through a whirlpool hash but "pip install whirlpool" failed compilation so I skipped that
        characters = string.ascii_letters + string.digits
        return "".join(random.choice(characters) for i in range(length))

    def check_auth_header(auth_header):
        result = False
        if auth_header is None:
            LOGGER.info(f"No Auth header present. all headers: {request.headers}")
            return False

        if not auth_header.strip().startswith("Signature"):
            LOGGER.info("Missing Signature in Authorization header!")
            return False

        return True

    def get_key_id(sig_block):
        key_id = sig_block.get("keyId")
        if not key_id:
            LOGGER.debug("Missing keyId")
            return None

        LOGGER.info(f"Found keyId = {key_id}")
        parsed_key_id = urlparse(key_id)
        if parsed_key_id.scheme.startswith("http"):
            key_id = urlunparse(
                (
                    parsed_key_id.scheme,
                    parsed_key_id.netloc,
                    parsed_key_id.path,
                    parsed_key_id.params,
                    "",
                    "",
                )
            )
        else:
            key_id = re.sub("acct:", "", key_id)

        return key_id

    auth_header = request.headers.get("Authorization", None)
    LOGGER.info(f"Auth header: {auth_header}")
    if not check_auth_header(auth_header):
        return JsonResponse(ret_response)

    sig_block = parse_sigheader(auth_header)
    key_id = get_key_id(sig_block)
    if not key_id:
        return JsonResponse(ret_response)

    LOGGER.info(f"cleaned keyId = {key_id}")

    # now find the user with this keyId
    remote_user_from_cache = remote_user_cache.get(
        create_cache_key_from_remote_user(key_id)
    )
    if remote_user_from_cache is None:
        remote_user_from_cache = try_fetch_remote_user(key_id)
    else:
        LOGGER.info(f"Remote user {key_id} found in cache!")

    if remote_user_from_cache is None:
        LOGGER.info(f"Failed to retrieve user's public key for {key_id}")
        return JsonResponse(ret_response)

    public_key = load_pem_public_key(remote_user_from_cache["pubkey"])
    verified = sig_verify(request, sig_block, public_key)
    if not verified:
        # maybe the cached user had an outdated public key - fetch most recent public key
        remote_user_from_cache = try_fetch_remote_user(key_id)
        if not remote_user_from_cache:
            LOGGER.info(f"Failed to retrieve user's public key for {key_id}")
            return JsonResponse(ret_response)

        public_key = load_pem_public_key(remote_user_from_cache["pubkey"])
        verified = sig_verify(request, sig_block, public_key)

    if not verified:
        LOGGER.info("Signature verification failed")
        return JsonResponse(ret_response)

    LOGGER.info("Signature OK")

    address = remote_user_from_cache["address"]
    # generate and store the OWA token
    token = generate_token()
    owa_verification = OwaVerification(token=token, remote_url=address)
    await owa_verification.asave()

    # encrypt the token with the public key of the remote user
    encrypted_token = base64.b64encode(
        public_key.encrypt(token.encode(), padding.PKCS1v15())
    ).decode()

    avatar_link = remote_user_from_cache["avatar_link"]
    LOGGER.debug(f"Address: {address} - Avatar link: {avatar_link}")
    if avatar_link:
        # Try using avatar specific cache if available
        try:
            cache = caches["avatar"]
        except InvalidCacheBackendError:
            cache = caches["default"]

        # 24 is just one of the ALLOWED_SIZES.
        # Assumption is that, if one of them is there, all sizes will be found from cache
        avatar_image = cache.get(get_avatar_cache_key(address, 24))
        if avatar_image is None:
            LOGGER.info(f"Requesting avatar on {avatar_link}")
            avatar_image = weblate_request("get", avatar_link)
            for size in ALLOWED_SIZES:
                store_avatar_image(avatar_image, size)
        else:
            LOGGER.info("Avatar found in cache!")

    ret_response["success"] = "true"
    ret_response["encrypted_token"] = encrypted_token

    return JsonResponse(ret_response)
