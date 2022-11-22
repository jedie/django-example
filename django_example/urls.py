from bx_django_utils.admin_extra_views.registry import extra_view_registry
from django.contrib import admin
from django.urls import include, path

from django_example.views import DebugView, LoginRequiredView, SSOwatLoginRedirectView


urlpatterns = [
    path('', DebugView.as_view(), name='debug-view'),
    path('login-required/', LoginRequiredView.as_view(), name='login-required-view'),
    #
    # Cover over the default Django Admin Login with SSOWat login:
    path('admin/login/', SSOwatLoginRedirectView.as_view(), name='ssowat-login'),
    #
    path('admin/', include(extra_view_registry.get_urls())),
    path('admin/', admin.site.urls),
]
