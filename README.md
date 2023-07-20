# OnlineSchool-DRF-RestApi

### create account app
```commandline
python manage.py startapp account
```


### .env file
```ini
EMAIL_USER=user@email.com
EMAIL_PASS=email_password
EMAIL_FROM=user@email.com
```

### settings.py file added email configuration
```python
import os
# Email Configuration
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = os.environ.get('EMAIL_USER')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_PASS')
EMAIL_USE_TLS = True
PASSWORD_RESET_TIMEOUT = 900
```

### for static and media file add in settings.py
```python
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
```

### for image file in model install
```commandline
pip install pillow
```
