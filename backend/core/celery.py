import os
from celery import Celery
from celery.signals import worker_ready

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
app = Celery('core')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

@worker_ready.connect
def cleanup_orphaned_scans(sender, **kwargs):
    import django
    django.setup()
    from scanners.models import ScanResult
    orphaned = ScanResult.objects.filter(report_data__scan_status='running')
    for r in orphaned:
        r.report_data['scan_status'] = 'stopped'
        r.save(update_fields=['report_data'])
