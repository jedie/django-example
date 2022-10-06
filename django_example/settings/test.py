from django_example.settings.prod import *  # noqa:F401,F403


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'django-example',
        'DEBUG_NAME': 'django-example',
    },
}
