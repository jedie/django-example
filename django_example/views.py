import getpass
import logging
import os
import sys
from pathlib import Path
from typing import Union

from django.conf import settings
from django.http import HttpRequest
from django.views.generic import TemplateView

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
