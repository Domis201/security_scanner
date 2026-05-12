from django.db import models

class ScanProfile(models.Model):
    OPENVAS_CONFIGS = [
        ('base', 'Base'),
        ('discovery', 'Discovery'),
        ('full_and_fast', 'Full and fast'),
    ]
    SCHEDULES = [
        ('none', 'Nėra'),
        ('hourly', 'Kas valandą'),
        ('daily', 'Kas dieną'),
        ('weekly', 'Kas savaitę'),
    ]
    name = models.CharField(max_length=100)
    target_ip = models.CharField(max_length=255)
    intensity = models.CharField(max_length=20)
    use_openvas = models.BooleanField(default=True)
    nmap_version_scan = models.BooleanField(default=False)
    openvas_config = models.CharField(max_length=20, choices=OPENVAS_CONFIGS, default='base')
    schedule = models.CharField(max_length=20, choices=SCHEDULES, default='none')
    schedule_time = models.CharField(max_length=5, default='08:00')
    schedule_weekday = models.IntegerField(default=0)
    next_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

# Įsitikink, kad pavadinimas sutampa su tuo, ko ieško admin.py
class ScanResult(models.Model): 
    profile = models.ForeignKey(ScanProfile, on_delete=models.CASCADE)
    report_data = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
