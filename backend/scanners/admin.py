from django.contrib import admin
from .models import ScanProfile, ScanResult

@admin.register(ScanProfile)
class ScanProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'target_ip', 'intensity', 'created_at')
    search_fields = ('name', 'target_ip')

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    # Kadangi ScanResult saugo duomenis JSON formatu (report_data), 
    # rodome ryšį su profiliu ir sukūrimo laiką.
    list_display = ('profile', 'created_at')
    list_filter = ('created_at',)
