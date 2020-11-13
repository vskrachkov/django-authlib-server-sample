import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'oauth2_server_sample.settings')

application = get_asgi_application()
