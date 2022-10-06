from bx_django_utils.test_utils.html_assertion import HtmlAssertionMixin
from django.conf import settings
from django.test.testcases import TestCase
from django.urls.base import reverse


class SSOwatLoginRedirectViewTestCase(HtmlAssertionMixin, TestCase):
    def test_view(self):
        self.assertEqual(reverse('admin:login'), '/admin/login/')
        self.assertEqual(reverse('ssowat-login'), '/admin/login/')
        self.assertEqual(settings.LOGIN_REDIRECT_URL, '/')

        with self.assertLogs('django_example') as logs:
            response = self.client.get(path='/admin/login/', secure=True)
            self.assertRedirects(
                response,
                expected_url='/yunohost/sso/?r=aHR0cHM6Ly90ZXN0c2VydmVyLw%3D%3D',
                fetch_redirect_response=False,
            )
        self.assertEqual(
            logs.output,
            [
                'INFO:django_example.views:'
                'Redirect to SSOwat login with return URI: "https://testserver/"'
            ],
        )

        with self.assertLogs('django_example') as logs:
            response = self.client.get(path='/admin/login/?next=%2Flogin-required%2F', secure=True)
            self.assertRedirects(
                response,
                expected_url='/yunohost/sso/?r=aHR0cHM6Ly90ZXN0c2VydmVyL2xvZ2luLXJlcXVpcmVkLw%3D%3D',
                fetch_redirect_response=False,
            )
        self.assertEqual(
            logs.output,
            [
                'INFO:django_example.views:'
                'Redirect to SSOwat login with return URI: "https://testserver/login-required/"'
            ],
        )

        # host must be allowed:
        with self.assertLogs('django_example') as logs:
            response = self.client.get(path='/admin/login/?next=https://hacker.tld/', secure=True)
            self.assertRedirects(
                response,
                expected_url='/yunohost/sso/?r=aHR0cHM6Ly90ZXN0c2VydmVyLw%3D%3D',
                fetch_redirect_response=False,
            )
        self.assertEqual(
            logs.output,
            [
                'INFO:django_example.views:'
                'Redirect to SSOwat login with return URI: "https://testserver/"'
            ],
        )
