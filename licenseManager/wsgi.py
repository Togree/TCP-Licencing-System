"""
WSGI config for licenseManager project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

# Ensure RSA keys are generated
from licenses.utils import generate_rsa_key_pair
generate_rsa_key_pair()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'licenseManager.settings')

application = get_wsgi_application()
