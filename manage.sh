#!/bin/sh

export DJANGO_SETTINGS_MODULE=django_example.settings.local

exec poetry run python3 manage.py "$@"
