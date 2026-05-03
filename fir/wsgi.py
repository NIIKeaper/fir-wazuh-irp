"""
WSGI config for FIR project.
It exposes the WSGI callable as a module-level variable named ``application``.
For more information on this file, see
https://docs.djangoproject.com/en/1.9/howto/deployment/wsgi/
"""

import os
import sys

# 🐛 FIX: Убираем дублирование путей в sys.path, которое добавляет uWSGI
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Нормализуем все пути в абсолютные и убираем '.' и пустые строки
sys.path = [os.path.abspath(p) for p in sys.path if p not in ('.', '')]
# Убираем дубликаты, сохраняя порядок
seen = set()
sys.path = [p for p in sys.path if not (p in seen or seen.add(p))]
# Убеждаемся, что корень проекта первым в sys.path
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fir.config.production')

application = get_wsgi_application()
