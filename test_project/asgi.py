"""
ASGI config for test_project project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""
import os
from django.core.asgi import get_asgi_application
from kante.router import router

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "test_project.settings")
# Initialize Django ASGI application early to ensure the AppRegistry
# is populated before importing code that may import ORM models.
django_asgi_app = get_asgi_application()


from .schema import schema  # noqa



application = router(
    schema,
    django_asgi_app,
)