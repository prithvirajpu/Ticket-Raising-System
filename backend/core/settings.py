from pathlib import Path
import os
from datetime import timedelta
from celery.schedules import crontab
from dotenv import load_dotenv
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG')=='True'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS','').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    'apps.core_app',
    'apps.accounts',
    'apps.users',
    'apps.admins',
    'apps.agents',
    'apps.clients',
    'apps.teamleads',
    'apps.managers',
    'apps.tickets',
    'apps.payments',
    

    'rest_framework',
    'corsheaders',
    'channels',

    'cloudinary',
    'cloudinary_storage',

    'django_celery_beat',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
WSGI_APPLICATION = 'core.wsgi.application'
ASGI_APPLICATION = 'core.asgi.application'

DATABASES = {
    'default': dj_database_url.parse(
        os.getenv('DATABASE_URL'),
        conn_max_age=600,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

CLOUDINARY_STORAGE = {
    "CLOUD_NAME": os.getenv("CLOUDINARY_CLOUD_NAME"),
    "API_KEY": os.getenv("CLOUDINARY_API_KEY"),
    "API_SECRET": os.getenv("CLOUDINARY_API_SECRET"),
    "RESOURCE_TYPE": "raw",
}

STORAGES = {
    "default": {
        "BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },

    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'debug.log'),
            'formatter': 'verbose',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },

    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
        },
    },
}

if not DEBUG:
    LOGGING["handlers"].pop("file", None)

    LOGGING["loggers"]["django"]["handlers"] = ["console"]
    LOGGING["loggers"][""]["handlers"] = ["console"]
    
EMAIL_BACKEND=os.getenv('EMAIL_BACKEND')
EMAIL_HOST=os.getenv('EMAIL_HOST')
EMAIL_PORT=os.getenv('EMAIL_PORT')
EMAIL_USE_TLS=os.getenv('EMAIL_USE_TLS')
EMAIL_HOST_USER=os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD=os.getenv('EMAIL_HOST_PASSWORD')

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

if DEBUG:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
else:
    CORS_ALLOWED_ORIGINS = os.getenv(
        "CORS_ALLOWED_ORIGINS",
        ""
    ).split(",")

CORS_ALLOW_CREDENTIALS = True

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

if DEBUG:
    CSRF_TRUSTED_ORIGINS = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://trs.prithvirajpu.online",
    ]
else:
    CSRF_TRUSTED_ORIGINS = os.getenv(
        "CSRF_TRUSTED_ORIGINS",
        ""
    ).split(",")

CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG

SECURE_PROXY_SSL_HEADER = (
    "HTTP_X_FORWARDED_PROTO",
    "https",
)
USE_X_FORWARDED_HOST = True

SIMPLE_JWT={
    "ACCESS_TOKEN_LIFETIME":timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME":timedelta(days=1),
    "AUTH_HEADER_TYPES":("Bearer",),
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
AUTH_USER_MODEL = 'accounts.User'

GOOGLE_CLIENT_ID = os.getenv('My_GOOGLE_CLIENT_ID')

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://redis:6379/0"
)
CELERY_BROKER_URL = REDIS_URL
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'

CELERY_BEAT_SCHEDULE = {
    "auto-assign-every-1-minute": {
        "task": "apps.tickets.tasks.auto_assign_task",
        "schedule": 60.0,
    },
    'monthly-salary-distribution':{
        'task':'apps.payments.tasks.monthly_salary_distribution_task',
        # 'schedule': crontab(day_of_month=1, hour=0,minute=0)
        'schedule':60.0,
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [{
                "address": REDIS_URL,
                "max_connections": 20,
            }],
        }
    },
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "CONNECTION_POOL_KWARGS": {
                "max_connections": 10,
                "retry_on_timeout": True,
            },
        }
    }
}


STRIPE_SECRET_KEY=os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY=os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET=os.getenv('STRIPE_WEBHOOK_SECRET')

RESEND_API_KEY =os.getenv('RESEND_API_KEY')
EMAIL_FROM = os.getenv("EMAIL_FROM")

FRONTEND_URL = os.getenv("FRONTEND_URL")