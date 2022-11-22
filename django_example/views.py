import base64
import getpass
import logging
import os
import sys
from pathlib import Path
from typing import Union
from urllib.parse import ParseResult, urlparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import RedirectURLMixin
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import RedirectView, TemplateView

from django_example import __version__


logger = logging.getLogger(__name__)


def get_real_ip(request: HttpRequest) -> Union[str, None]:
    return request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')


def show_details(request: HttpRequest) -> bool:
    if request.user.is_authenticated:
        return True
    return settings.DEBUG and get_real_ip(request) in settings.INTERNAL_IPS


class DebugView(TemplateView):
    template_name = 'django_example/debug_view.html'

    def get(self, request, *args, **kwargs):
        logger.info('DebugView request from user: %s', request.user)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **context):
        request: HttpRequest = self.request
        context.update(
            dict(
                version=__version__,
                user=request.user,
                env_type=settings.ENV_TYPE,
                settings_module=settings.SETTINGS_MODULE,
                remote_addr=get_real_ip(request),
            )
        )
        if show_details(request):
            ruid, euid, suid = os.getresuid()
            rgid, egid, sgid = os.getresgid()
            context.update(
                dict(
                    cwd=Path().cwd(),
                    python_version=sys.version,
                    executable=sys.executable,
                    sys_prefix=sys.prefix,
                    os_uname=' '.join(os.uname()),
                    process_user=getpass.getuser(),
                    user_id=ruid,
                    user_group_id=rgid,
                    pid=os.getpid(),
                    environ=dict(os.environ),
                    meta=request.META,
                )
            )
        return super().get_context_data(**context)


class LoginRequiredView(LoginRequiredMixin, RedirectView):
    pattern_name = 'admin:index'

    def handle_no_permission(self):
        logger.info('User: "%s" do not pass the "LoginRequired" check', self.request.user)
        return super().handle_no_permission()

    def get(self, request, *args, **kwargs):
        logger.info('User: "%s" pass the "LoginRequired" check, ok.', request.user)
        messages.success(request, 'You pass the "LoginRequired" check, ok.')
        return super().get(request, *args, **kwargs)


def redirect_to_ssowat_login(request, next: str):
    """
    Redirect to SSOwat login with given "next" return url.

    TODO: Move to https://github.com/YunoHost-Apps/django_yunohost_integration
    """
    if not url_has_allowed_host_and_scheme(
        url=next,
        allowed_hosts=[request.get_host()],
        require_https=request.is_secure(),
    ):
        logger.error('Next url "%s" is not safe! Fallback to LOGIN_REDIRECT_URL', next)
        next = f'{request.scheme}://{request.get_host()}/{settings.LOGIN_REDIRECT_URL.rstrip("/")}'

    next_bytes = next.encode(encoding='UTF8')
    next_encoded_bytes: bytes = base64.urlsafe_b64encode(next_bytes)
    next_encoded = next_encoded_bytes.decode(encoding='ASCII')
    ssowat_uri = f'/yunohost/sso/?r={next_encoded}'
    logger.info('Redirect to SSOwat login with return URI: "%s"', next)
    return HttpResponseRedirect(ssowat_uri)


class SSOwatLoginRedirectView(RedirectURLMixin, View):
    """
    This view should be registered in urls with LOGIN_URL, e.g.:

        urlpatterns = [
            path('login/', SSOwatLoginRedirectView.as_view(), name='ssowat-login'),
        ]
        settings.LOGIN_URL='ssowat-login'

    TODO: Move to https://github.com/YunoHost-Apps/django_yunohost_integration
    """

    next_page = settings.LOGIN_REDIRECT_URL
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url_allowed_hosts = set()

    def get(self, request):
        user = request.user
        redirect_url = self.get_success_url()
        result: ParseResult = urlparse(redirect_url)
        if not result.scheme:
            redirect_url = f'{request.scheme}://{request.get_host()}{result.path}'

        if user.is_authenticated:
            logger.info('User "%s" already authenticated: Redirect to: %s', user, redirect_url)
            return HttpResponseRedirect(redirect_url)

        uri_encoded_bytes: bytes = base64.urlsafe_b64encode(redirect_url.encode(encoding='UTF8'))
        uri_encoded = uri_encoded_bytes.decode(encoding='ASCII')
        ssowat_uri = f'/yunohost/sso/?r={uri_encoded}'
        logger.info('Redirect to SSOwat login with return URI: "%s"', redirect_url)
        return HttpResponseRedirect(ssowat_uri)
