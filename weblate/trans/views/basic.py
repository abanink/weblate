# Copyright © Michal Čihař <michal@weblate.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import re

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.html import format_html
from django.utils.http import urlencode
from django.utils.translation import gettext
from django.views.decorators.cache import never_cache
from django.views.generic import RedirectView

from weblate.formats.models import EXPORTERS
from weblate.lang.models import Language
from weblate.trans.exceptions import FileParseError
from weblate.trans.forms import (
    AddCategoryForm,
    AnnouncementForm,
    AutoForm,
    BulkEditForm,
    CategoryDeleteForm,
    CategoryLanguageDeleteForm,
    CategoryRenameForm,
    ComponentDeleteForm,
    ComponentRenameForm,
    DownloadForm,
    ProjectDeleteForm,
    ProjectFilterForm,
    ProjectLanguageDeleteForm,
    ProjectRenameForm,
    ReplaceForm,
    ReportsForm,
    SearchForm,
    TranslationDeleteForm,
    get_new_language_form,
    get_new_unit_form,
    get_upload_form,
)
from weblate.trans.models import (
    Category,
    Change,
    Component,
    ComponentList,
    Project,
    Translation,
)
from weblate.trans.models.component import prefetch_tasks, translation_prefetch_tasks
from weblate.trans.models.project import prefetch_project_flags
from weblate.trans.models.translation import GhostTranslation
from weblate.trans.util import render, sort_unicode, translation_percent
from weblate.utils import messages
from weblate.utils.ratelimit import reset_rate_limit, session_ratelimit_post
from weblate.utils.stats import (
    CategoryLanguage,
    GhostProjectLanguageStats,
    ProjectLanguage,
    prefetch_stats,
)
from weblate.utils.views import (
    get_paginator,
    optional_form,
    parse_path,
    show_form_errors,
    try_set_language,
)
from weblate.logger import LOGGER
from asgiref.sync import async_to_sync
from urllib.parse import urlparse, urlunparse, urlsplit, urlunsplit
import string
import random
from weblate.trans.models.owa_verification import OwaVerification
import base64
from weblate.accounts.avatar import get_avatar_cache_key
from django.core.cache import InvalidCacheBackendError, caches
from weblate.utils.requests import request as weblate_request
from requests.exceptions import JSONDecodeError
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from weblate.accounts.views import ALLOWED_SIZES
import io
from PIL import Image

@never_cache
def list_projects(request):
    """List all projects."""
    query_string = ""
    projects = request.user.allowed_projects
    form = ProjectFilterForm(request.GET)
    if form.is_valid():
        query = {}
        if form.cleaned_data["owned"]:
            user = form.cleaned_data["owned"]
            query["owned"] = user.username
            projects = (user.owned_projects & projects.distinct()).order()
        elif form.cleaned_data["watched"]:
            user = form.cleaned_data["watched"]
            query["watched"] = user.username
            projects = (user.watched_projects & projects).order()
        query_string = urlencode(query)
    else:
        show_form_errors(request, form)

    return render(
        request,
        "projects.html",
        {
            "allow_index": True,
            "projects": prefetch_project_flags(
                get_paginator(request, prefetch_stats(projects))
            ),
            "title": gettext("Projects"),
            "query_string": query_string,
        },
    )


def add_ghost_translations(component, user, translations, generator, **kwargs):
    """Adds ghost translations for user languages to the list."""
    if component.can_add_new_language(user, fast=True):
        existing = {translation.language.code for translation in translations}
        for language in user.profile.all_languages:
            if language.code in existing:
                continue
            code = component.format_new_language_code(language)
            if re.match(component.language_regex, code) is None:
                continue
            translations.append(generator(component, language, **kwargs))


def show_engage(request, path):
    # Legacy URL
    if len(path) == 2:
        return redirect("engage", permanent=True, path=[path[0], "-", path[1]])
    # Get project object, skipping ACL
    obj = parse_path(request, path, (ProjectLanguage, Project), skip_acl=True)

    translate_object = None
    if isinstance(obj, ProjectLanguage):
        language = obj.language
        try_set_language(language.code)
        translate_object = obj
        project = obj.project
        stats_obj = obj.stats

        all_count = strings_count = stats_obj.all
        translated_count = stats_obj.translated

        # Remove glossary from counts
        glossaries = prefetch_stats(
            Translation.objects.filter(
                language=language, component__in=project.glossaries
            ).prefetch()
        )
        for glossary in prefetch_stats(glossaries):
            all_count -= glossary.stats.all
            translated_count -= glossary.stats.translated
            strings_count -= glossary.stats.all

    else:
        project = obj
        language = None
        guessed_language = (
            Language.objects.filter(translation__component__project=obj)
            .exclude(component__project=obj)
            .distinct()
            .get_request_language(request)
        )
        if guessed_language:
            translate_object = ProjectLanguage(
                project=project, language=guessed_language
            )
        stats_obj = obj.stats

        all_count = stats_obj.all
        strings_count = stats_obj.source_strings
        translated_count = stats_obj.translated

        # Remove glossary from counts
        for glossary in prefetch_stats(project.glossaries):
            all_count -= glossary.stats.all
            translated_count -= glossary.stats.translated
            strings_count -= glossary.stats.source_strings

    return render(
        request,
        "engage.html",
        {
            "allow_index": True,
            "object": obj,
            "path_object": obj,
            "project": project,
            "strings_count": strings_count,
            "languages_count": project.stats.languages,
            "percent": translation_percent(translated_count, all_count),
            "language": language,
            "translate_object": translate_object,
            "project_link": format_html(
                '<a href="{}">{}</a>', project.get_absolute_url(), project.name
            ),
            "title": gettext("Get involved in {0}!").format(project),
        },
    )


@never_cache
def show(request, path):
    obj = parse_path(
        request,
        path,
        (
            Translation,
            Component,
            Project,
            ProjectLanguage,
            Category,
            CategoryLanguage,
        ),
    )
    if isinstance(obj, Project):
        return show_project(request, obj)
    if isinstance(obj, Component):
        return show_component(request, obj)
    if isinstance(obj, ProjectLanguage):
        return show_project_language(request, obj)
    if isinstance(obj, Category):
        return show_category(request, obj)
    if isinstance(obj, CategoryLanguage):
        return show_category_language(request, obj)
    if isinstance(obj, Translation):
        return show_translation(request, obj)
    raise TypeError(f"Not supported show: {obj}")


def show_project_language(request, obj):
    language_object = obj.language
    project_object = obj.project
    user = request.user

    last_changes = Change.objects.last_changes(
        user, project=project_object, language=language_object
    ).recent()

    translations = translation_prefetch_tasks(prefetch_stats(obj.translation_set))

    # Add ghost translations
    if user.is_authenticated:
        existing = {translation.component.slug for translation in translations}
        missing = project_object.get_child_components_filter(
            lambda qs: qs.exclude(slug__in=existing)
        )
        translations.extend(
            GhostTranslation(component, language_object)
            for component in missing
            if component.can_add_new_language(user, fast=True)
        )

    return render(
        request,
        "language-project.html",
        {
            "allow_index": True,
            "language": language_object,
            "project": project_object,
            "object": obj,
            "path_object": obj,
            "last_changes": last_changes,
            "translations": translations,
            "title": f"{project_object} - {language_object}",
            "search_form": SearchForm(
                user, language=language_object, initial=SearchForm.get_initial(request)
            ),
            "licenses": project_object.component_set.exclude(license="").order_by(
                "license"
            ),
            "language_stats": project_object.stats.get_single_language_stats(
                language_object
            ),
            "delete_form": optional_form(
                ProjectLanguageDeleteForm, user, "translation.delete", obj, obj=obj
            ),
            "replace_form": optional_form(ReplaceForm, user, "unit.edit", obj),
            "bulk_state_form": optional_form(
                BulkEditForm,
                user,
                "translation.auto",
                obj,
                user=user,
                obj=obj,
                project=obj.project,
            ),
        },
    )


def show_category_language(request, obj):
    language_object = obj.language
    category_object = obj.category
    user = request.user

    last_changes = (
        Change.objects.last_changes(user, language=language_object)
        .for_category(category_object)
        .recent()
    )

    translations = list(obj.translation_set)

    # Add ghost translations
    if user.is_authenticated:
        existing = {translation.component.slug for translation in translations}
        missing = category_object.component_set.exclude(slug__in=existing)
        translations.extend(
            GhostTranslation(component, language_object)
            for component in missing
            if component.can_add_new_language(user, fast=True)
        )

    return render(
        request,
        "category-project.html",
        {
            "allow_index": True,
            "language": language_object,
            "category": category_object,
            "object": obj,
            "path_object": obj,
            "last_changes": last_changes,
            "translations": translations,
            "title": f"{category_object} - {language_object}",
            "search_form": SearchForm(
                user, language=language_object, initial=SearchForm.get_initial(request)
            ),
            "licenses": obj.category.get_child_components_access(user)
            .exclude(license="")
            .order_by("license"),
            "language_stats": category_object.stats.get_single_language_stats(
                language_object
            ),
            "delete_form": optional_form(
                CategoryLanguageDeleteForm, user, "translation.delete", obj, obj=obj
            ),
            "replace_form": optional_form(ReplaceForm, user, "unit.edit", obj),
            "bulk_state_form": optional_form(
                BulkEditForm,
                user,
                "translation.auto",
                obj,
                user=user,
                obj=obj,
                project=obj.category.project,
            ),
        },
    )


def show_project(request, obj):
    user = request.user

    all_changes = obj.change_set.prefetch()
    last_changes = all_changes.recent()
    last_announcements = all_changes.filter_announcements().recent()

    all_components = obj.get_child_components_access(
        user, lambda qs: qs.filter(category=None)
    )
    all_components = get_paginator(request, prefetch_stats(all_components))
    for component in all_components:
        component.is_shared = None if component.project == obj else component.project

    language_stats = obj.stats.get_language_stats()
    # Show ghost translations for user languages
    component = None
    for component in all_components:
        if component.can_add_new_language(user, fast=True):
            break
    if component:
        add_ghost_translations(
            component,
            user,
            language_stats,
            GhostProjectLanguageStats,
            is_shared=component.is_shared,
        )

    language_stats = sort_unicode(
        language_stats, user.profile.get_translation_orderer(request)
    )

    components = prefetch_tasks(all_components)

    return render(
        request,
        "project.html",
        {
            "allow_index": True,
            "object": obj,
            "path_object": obj,
            "project": obj,
            "last_changes": last_changes,
            "last_announcements": last_announcements,
            "reports_form": ReportsForm({"project": obj}),
            "language_stats": [stat.obj or stat for stat in language_stats],
            "search_form": SearchForm(
                request.user, initial=SearchForm.get_initial(request)
            ),
            "announcement_form": optional_form(
                AnnouncementForm, user, "project.edit", obj
            ),
            "add_form": AddCategoryForm(request, obj) if obj.can_add_category else None,
            "delete_form": optional_form(
                ProjectDeleteForm, user, "project.edit", obj, obj=obj
            ),
            "rename_form": optional_form(
                ProjectRenameForm,
                user,
                "project.edit",
                obj,
                request=request,
                instance=obj,
            ),
            "replace_form": optional_form(ReplaceForm, user, "unit.edit", obj),
            "bulk_state_form": optional_form(
                BulkEditForm,
                user,
                "translation.auto",
                obj,
                user=user,
                obj=obj,
                project=obj,
            ),
            "components": components,
            "categories": obj.category_set.filter(category=None),
            "licenses": sorted(
                (component for component in all_components if component.license),
                key=lambda component: component.license,
            ),
        },
    )


def show_category(request, obj):
    user = request.user

    all_changes = Change.objects.for_category(obj).prefetch()
    last_changes = all_changes.recent()
    last_announcements = all_changes.filter_announcements().recent()

    all_components = obj.get_child_components_access(user)
    all_components = get_paginator(request, prefetch_stats(all_components))

    language_stats = obj.stats.get_language_stats()
    # Show ghost translations for user languages
    component = None
    for component in all_components:
        if component.can_add_new_language(user, fast=True):
            break
    if component:
        add_ghost_translations(
            component,
            user,
            language_stats,
            GhostProjectLanguageStats,
        )

    orderer = user.profile.get_translation_orderer(request)
    language_stats = sort_unicode(
        language_stats,
        lambda x: f"{orderer(x)}-{x.language}",
    )

    components = prefetch_tasks(all_components)

    return render(
        request,
        "category.html",
        {
            "allow_index": True,
            "object": obj,
            "path_object": obj,
            "project": obj,
            "add_form": AddCategoryForm(request, obj) if obj.can_add_category else None,
            "last_changes": last_changes,
            "last_announcements": last_announcements,
            "language_stats": [stat.obj or stat for stat in language_stats],
            "search_form": SearchForm(user, initial=SearchForm.get_initial(request)),
            "delete_form": optional_form(
                CategoryDeleteForm, user, "project.edit", obj, obj=obj
            ),
            "rename_form": optional_form(
                CategoryRenameForm,
                user,
                "project.edit",
                obj,
                request=request,
                instance=obj,
            ),
            "replace_form": optional_form(ReplaceForm, user, "unit.edit", obj),
            "bulk_state_form": optional_form(
                BulkEditForm,
                user,
                "translation.auto",
                obj,
                user=user,
                obj=obj,
                project=obj.project,
            ),
            "components": components,
            "categories": obj.category_set.all(),
            "licenses": sorted(
                (component for component in all_components if component.license),
                key=lambda component: component.license,
            ),
        },
    )


def show_component(request, obj):
    user = request.user

    last_changes = obj.change_set.prefetch().recent(skip_preload="component")

    translations = prefetch_stats(list(obj.translation_set.prefetch()))

    # Show ghost translations for user languages
    add_ghost_translations(obj, user, translations, GhostTranslation)

    translations = sort_unicode(
        translations, user.profile.get_translation_orderer(request)
    )

    return render(
        request,
        "component.html",
        {
            "allow_index": True,
            "object": obj,
            "path_object": obj,
            "project": obj.project,
            "component": obj,
            "translations": translations,
            "reports_form": ReportsForm({"component": obj}),
            "last_changes": last_changes,
            "replace_form": optional_form(ReplaceForm, user, "unit.edit", obj),
            "bulk_state_form": optional_form(
                BulkEditForm,
                user,
                "translation.auto",
                obj,
                user=user,
                obj=obj,
                project=obj.project,
            ),
            "announcement_form": optional_form(
                AnnouncementForm, user, "component.edit", obj
            ),
            "delete_form": optional_form(
                ComponentDeleteForm, user, "component.edit", obj, obj=obj
            ),
            "rename_form": optional_form(
                ComponentRenameForm,
                user,
                "component.edit",
                obj,
                request=request,
                instance=obj,
            ),
            "search_form": SearchForm(
                request.user, initial=SearchForm.get_initial(request)
            ),
            "alerts": obj.all_active_alerts
            if "alerts" not in request.GET
            else obj.alert_set.all(),
        },
    )


def show_translation(request, obj):
    component = obj.component
    project = component.project
    last_changes = obj.change_set.prefetch().recent(skip_preload="translation")
    user = request.user

    # Get form
    form = get_upload_form(user, obj)

    search_form = SearchForm(
        request.user, language=obj.language, initial=SearchForm.get_initial(request)
    )

    # Translations to same language from other components in this project
    # Show up to 10 of them, needs to be list to append ghost ones later
    other_translations = translation_prefetch_tasks(
        prefetch_stats(
            list(
                Translation.objects.prefetch()
                .filter(component__project=project, language=obj.language)
                .exclude(pk=obj.pk)[:10]
            )
        )
    )

    # Include ghost translations for other components, this
    # adds quick way to create translations in other components
    if len(other_translations) < 10:
        existing = {translation.component.slug for translation in other_translations}
        existing.add(component.slug)
        for test_component in project.child_components:
            if test_component.slug in existing:
                continue
            if test_component.can_add_new_language(user, fast=True):
                other_translations.append(
                    GhostTranslation(test_component, obj.language)
                )

    return render(
        request,
        "translation.html",
        {
            "allow_index": True,
            "path_object": obj,
            "object": obj,
            "project": project,
            "component": obj.component,
            "form": form,
            "download_form": DownloadForm(obj, auto_id="id_dl_%s"),
            "autoform": optional_form(
                AutoForm,
                user,
                "translation.auto",
                obj,
                obj=component,
                user=user,
            ),
            "search_form": search_form,
            "replace_form": optional_form(ReplaceForm, user, "unit.edit", obj),
            "bulk_state_form": optional_form(
                BulkEditForm,
                user,
                "translation.auto",
                obj,
                user=user,
                obj=obj,
                project=project,
            ),
            "new_unit_form": get_new_unit_form(obj, user),
            "announcement_form": optional_form(
                AnnouncementForm, user, "component.edit", obj
            ),
            "delete_form": optional_form(
                TranslationDeleteForm, user, "translation.delete", obj, obj=obj
            ),
            "last_changes": last_changes,
            "other_translations": other_translations,
            "exporters": EXPORTERS.list_exporters(obj),
        },
    )


@never_cache
def data_project(request, project):
    obj = parse_path(request, [project], (Project,))
    return render(
        request,
        "data.html",
        {
            "object": obj,
            "components": obj.get_child_components_access(request.user),
            "project": obj,
        },
    )


@never_cache
@login_required
@session_ratelimit_post("language", logout_user=False)
@transaction.atomic
def new_language(request, path):
    obj = parse_path(request, path, (Component,))
    user = request.user

    form_class = get_new_language_form(request, obj)
    can_add = obj.can_add_new_language(user)
    added = False

    if request.method == "POST":
        form = form_class(obj, request.POST)

        if form.is_valid():
            result = obj
            langs = form.cleaned_data["lang"]
            kwargs = {
                "user": user,
                "author": user,
                "component": obj,
                "details": {},
            }
            with obj.repository.lock:
                for language in Language.objects.filter(code__in=langs):
                    kwargs["details"]["language"] = language.code
                    if can_add:
                        translation = obj.add_new_language(
                            language, request, create_translations=False
                        )
                        if translation:
                            added = True
                            kwargs["translation"] = translation
                            if len(langs) == 1:
                                result = translation
                            obj.change_set.create(
                                action=Change.ACTION_ADDED_LANGUAGE, **kwargs
                            )
                    elif obj.new_lang == "contact":
                        obj.change_set.create(
                            action=Change.ACTION_REQUESTED_LANGUAGE, **kwargs
                        )
                        messages.success(
                            request,
                            gettext(
                                "A request for a new translation has been "
                                "sent to the project's maintainers."
                            ),
                        )
                try:
                    if added and not obj.create_translations(request=request):
                        messages.warning(
                            request,
                            gettext(
                                "The translation will be updated in the background."
                            ),
                        )
                except FileParseError:
                    pass
            if user.has_perm("component.edit", obj):
                reset_rate_limit("language", request)
            return redirect(result)
        messages.error(request, gettext("Please fix errors in the form."))
    else:
        form = form_class(obj)

    return render(
        request,
        "new-language.html",
        {
            "object": obj,
            "path_object": obj,
            "project": obj.project,
            "component": obj,
            "form": form,
            "can_add": can_add,
        },
    )


@never_cache
def healthz(request):
    """Simple health check endpoint."""
    return HttpResponse("ok")


@never_cache
def show_component_list(request, name):
    obj = get_object_or_404(ComponentList, slug__iexact=name)
    components = prefetch_tasks(
        prefetch_stats(obj.components.filter_access(request.user).prefetch())
    )

    return render(
        request,
        "component-list.html",
        {
            "object": obj,
            "components": components,
            "licenses": sorted(
                (component for component in components if component.license),
                key=lambda component: component.license,
            ),
        },
    )


@never_cache
def guide(request, path):
    obj = parse_path(request, path, (Component,))

    return render(
        request,
        "guide.html",
        {
            "object": obj,
            "path_object": obj,
            "project": obj.project,
            "component": obj,
            "guidelines": obj.guidelines,
        },
    )

@async_to_sync
async def owa_server(request):
    
    ret_response = { "success": "false" }
    LOGGER.info('Hit OWA endpoint')
   
    public_key = None 
    avatar_link = None
    keyId = None
    remote_user_cache = caches["default"]
    
    def perform_webfinger(url, domain = None):
        if not domain:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
        webfinger_url = f"https://{domain}/.well-known/webfinger?resource={url}"
        LOGGER.info(f"Performing webfinger lookup for url {url} on domain {domain}, calling {webfinger_url}")
        
        wf_response = weblate_request("get", webfinger_url)
        if wf_response.status_code != 200:
            LOGGER.info(f"Webfinger request failed, status code = {wf_response.status_code}")
            return None
      
        try:
            wf_result = wf_response.json()
        except JSONDecodeError as e:
            LOGGER.debug(f"Json parse error: {e}")
            return None
        
        LOGGER.debug(f"Webfinger result = {wf_result}")
        return wf_result 
    
    def webfinger_find_address(wf_result, check_routine = callable):
        subject = wf_result["subject"]
        if subject:
            subject = str(subject)
            if check_routine(subject):
                address = subject.removeprefix('acct:')
                LOGGER.debug(f"Address {address} found in subject")
                return address 
            
        address = None
        aliases = wf_result["aliases"]
        if aliases and isinstance(aliases, list):
            for a in aliases:
                a = str(a)
                if check_routine(a):
                    address = a.removeprefix('acct:')
                    LOGGER.debug(f"Address {address} found in alias") 
                    break
        
        return address
    
    # Check that a claimed address wil resolve to the keyId
    #
    # We will use the claimed address as username and in the key for caching the avatar
    # we need to make sure that this claimed address can be trusted
    # This can be done by looking up the keyId on the claimed address's domain
    # if it fails, someone is providing an invalid address to use as username
    def verify_address(address, keyId):
        domain = address.rpartition('@')[2]
        if not domain:
            return False
        
        wf_result = perform_webfinger(keyId, domain)
        return webfinger_find_address(wf_result, lambda address: address == keyId)
    
    def try_fetch_remote_user(keyId):
        wf_result = perform_webfinger(keyId)
        if not wf_result:
            LOGGER.debug(f"Webfinger failed for {keyId}")
            return None
        
        address = extract_address_from_webfinger(wf_result)
        verify_addr_result = verify_address(address, keyId)
        if not verify_addr_result:
            LOGGER.info(f"Address {address} could not be verified - this is a fatal error")
            return None
        
        LOGGER.info(f"Address verification passed for {address}")
        return store_remote_user_in_cache(keyId, wf_result)
            
    def extract_publickey_from_webfinger(wf_result):
        # extract public key from webfinger result
        pubkey_property = "https://w3id.org/security/v1#publicKeyPem"
        # TODO also return None if the public key is not a valid format?
        wf_properties = wf_result["properties"]
        if not wf_properties or not wf_properties[pubkey_property]:
            LOGGER.info(f"Unable to retrieve public key from webfinger")
            
        public_key = wf_properties[pubkey_property]
        LOGGER.debug(f"Public key retrieved: {public_key}") 
        return public_key
    
    def extract_address_from_webfinger(wf_result):
        # extract remote user address from webfinger
        # it could be in the subject or in the aliases
      
        address = webfinger_find_address(wf_result, lambda field: field.startswith('acct:'))  

        if address is None:
            LOGGER.info(f"Unable to retrieve address from webfinger")
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
                    LOGGER.debug(f"Found avatar link from webfinger response: {avatar_link}")
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
                       "avatar_link": avatar_link
                       }
        remote_user_cache.set(create_cache_key_from_remote_user(key), remote_user)
        return remote_user
    
    def parse_sigheader(header):
        ret = {}
        
        m = re.search(r'keyId="(.*?)"', header)
        if m:
            ret["keyId"] = m.group(1)
            
        m = re.search(r'created=([0-9]*)', header)
        if m:
            ret["created"] = m.group(1)
            
        m = re.search(r'expires=([0-9]*)', header)
        if m:
            ret["expires"] = m.group(1)
            
        m = re.search(r'algorithm="(.*?)"', header)
        if m:
            ret['algorithm'] = m.group(1)
            
        m = re.search(r'headers="(.*?)"', header)
        if m:
            ret['headers'] = m.group(1).split()
            
        m = re.search(r'signature="(.*?)"', header)
        if m:
            ret['signature'] = base64.b64decode(m.group(1).strip())
            
        if (ret.get("signature") and ret.get("algorithm") and (not ret.get("headers"))):
            ret["headers"] = ["date"]
            
        LOGGER.info(f"parse_sigheader: returning {ret}")
        return ret
    
    def sig_verify(request, sig_block, pubkey):
        LOGGER.info("Verify signature now...")
        
        headers = {k.lower(): v for k, v in dict(request.headers).items()}
        LOGGER.debug(f"Prepared headers: {headers}")
        headers["(request-target)"] = request.method.lower() + " " + request.get_full_path()
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
            signed_headers = [ 'date' ]
         
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
                    curr = datetime.strptime(h_val, '%a, %d %b %Y %H:%M:%S GMT') 
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
        resized_image.save(imgByteArr, format = 'PNG')
        avatar_image = imgByteArr.getvalue()
        
        avatar_cache_key = get_avatar_cache_key(address, size)
        cache.set(avatar_cache_key, avatar_image)
        
        LOGGER.info(f"Stored avatar for size {size} in cache at key {avatar_cache_key}")
    
    def generate_token(length = 32):
        # TODO this should be run through a whirlpool hash but "pip install whirlpool" failed compilation so I skipped that
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for i in range(length))
   
    auth_header = request.headers.get("Authorization", None)
    if auth_header is None:
        LOGGER.info(f"No Auth header present. all headers: {request.headers}")
        return JsonResponse(ret_response)
    LOGGER.info(f"Auth header: {auth_header}")
    
    if not auth_header.strip().startswith('Signature'):
        LOGGER.info('Missing Signature in Authorization header!')
        return JsonResponse(ret_response)
    
    sig_block = parse_sigheader(auth_header)
    keyId = sig_block.get("keyId")
    if not keyId:
        LOGGER.debug("Missing keyId")
        return JsonResponse(ret_response)

    LOGGER.info(f"Found keyId = {keyId}")
    parsed_keyId = urlparse(keyId)
    if parsed_keyId.scheme.startswith("http"):
        keyId = urlunparse((parsed_keyId.scheme, parsed_keyId.netloc, parsed_keyId.path, parsed_keyId.params, '', ''))
    else:
        keyId = re.sub("acct:", "", keyId)
   
    LOGGER.info(f"cleaned keyId = {keyId}")
    
    # now find the user with this keyId
    remote_user_from_cache = remote_user_cache.get(create_cache_key_from_remote_user(keyId))
    if remote_user_from_cache is None:
        remote_user_from_cache = try_fetch_remote_user(keyId)
    else:
        LOGGER.info(f"Remote user {keyId} found in cache!")
        
    if remote_user_from_cache is None:
        LOGGER.info(f"Failed to retrieve user's public key for {keyId}")
        return JsonResponse(ret_response) 
   
    public_key = load_pem_public_key(remote_user_from_cache["pubkey"])
    verified = sig_verify(request, sig_block, public_key)
    if not verified:
        # maybe the cached user had an outdated public key - fetch most recent public key
        remote_user_from_cache = try_fetch_remote_user(keyId)
        if not remote_user_from_cache:
            LOGGER.info(f"Failed to retrieve user's public key for {keyId}")
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
    owa_verification = OwaVerification(token = token, remote_url = address)
    await owa_verification.asave()
    
    # encrypt the token with the public key of the remote user
    encrypted_token = base64.b64encode(public_key.encrypt(token.encode(), padding.PKCS1v15())).decode()
  
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
           
class ProjectLanguageRedirectView(RedirectView):
    permanent = True
    query_string = True
    pattern_name = "show"

    def get_redirect_url(self, project: str | None, lang: str):
        return super().get_redirect_url(path=[project or "-", "-", lang])
