from django.apps import AppConfig

class FirMethodExtensionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'fir_method_extension'
    verbose_name = 'Extension: Incident Management Method'

    def ready(self):
        import fir_method_extension.signals  # noqa: F401