DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'security_db',
        'USER': 'root',
        'PASSWORD': 'Domka879DM',
        'HOST': 'db', # Jei naudosi Docker MySQL konteinerį
        'PORT': '3306',
    }
}
