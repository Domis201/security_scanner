from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from .models import ScanProfile, ScanResult
from .tasks import run_full_security_scan
from django.core.exceptions import ObjectDoesNotExist


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user:
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})
    return Response({'error': 'Neteisingas vartotojas arba slaptažodis'}, status=401)


def serialize_profile(profile):
    return {
        'id': profile.id,
        'name': profile.name,
        'target_ip': profile.target_ip,
        'intensity': profile.intensity,
        'use_openvas': profile.use_openvas,
        'nmap_version_scan': profile.nmap_version_scan,
        'openvas_config': profile.openvas_config,
        'schedule': profile.schedule,
        'schedule_time': profile.schedule_time,
        'schedule_weekday': profile.schedule_weekday,
        'next_run_at': profile.next_run_at.isoformat() if profile.next_run_at else None,
        'created_at': profile.created_at.isoformat(),
    }


def serialize_result(result):
    return {
        'id': result.id,
        'profile_id': result.profile_id,
        'created_at': result.created_at.isoformat(),
        'report_data': result.report_data or {},
    }

@api_view(['GET'])
def list_profiles(request):
    profiles = ScanProfile.objects.order_by('-created_at')
    return Response({'profiles': [serialize_profile(profile) for profile in profiles]})

@api_view(['POST'])
def create_profile(request):
    target_ip = request.data.get('target_ip')
    name = request.data.get('name', 'Quick scan profile')
    intensity = request.data.get('intensity', 'medium')
    use_openvas = request.data.get('use_openvas', True)
    nmap_version_scan = request.data.get('nmap_version_scan', False)
    openvas_config = request.data.get('openvas_config', 'base')
    schedule = request.data.get('schedule', 'none')
    schedule_time = request.data.get('schedule_time', '08:00')
    schedule_weekday = int(request.data.get('schedule_weekday', 0))

    if not target_ip:
        return Response({'status': 'error', 'message': 'target_ip is required'}, status=400)

    from django.utils import timezone
    from scanners.tasks import _next_run
    from types import SimpleNamespace
    next_run_at = _next_run(SimpleNamespace(schedule=schedule, schedule_time=schedule_time, schedule_weekday=schedule_weekday), timezone.now()) if schedule != 'none' else None

    profile = ScanProfile.objects.create(
        name=name,
        target_ip=target_ip,
        intensity=intensity,
        use_openvas=use_openvas,
        nmap_version_scan=nmap_version_scan,
        schedule=schedule,
        schedule_time=schedule_time,
        schedule_weekday=schedule_weekday,
        next_run_at=next_run_at,
        openvas_config=openvas_config,
    )

    return Response({'status': 'success', 'profile_id': profile.id, 'profile': serialize_profile(profile)})

@api_view(['POST'])
def start_profile_scan(request, profile_id):
    try:
        profile = ScanProfile.objects.get(id=profile_id)
    except ScanProfile.DoesNotExist:
        return Response({'status': 'error', 'message': 'Profile not found'}, status=404)

    run_full_security_scan.delay(profile.id, profile.target_ip)
    return Response({'status': 'success', 'profile_id': profile.id, 'message': 'Scan queued successfully'})

@api_view(['POST'])
def start_nmap_scan(request):
    target_ip = request.data.get('ip') or request.data.get('target_ip')
    name = request.data.get('name', 'Greitas skenavimas')
    intensity = request.data.get('intensity', 'low')
    use_openvas = request.data.get('use_openvas', True)
    nmap_version_scan = request.data.get('nmap_version_scan', False)
    openvas_config = request.data.get('openvas_config', 'base')

    if not target_ip:
        return Response({'status': 'error', 'message': 'IP adresas privalomas'}, status=400)

    profile = ScanProfile.objects.create(
        name=name,
        target_ip=target_ip,
        intensity=intensity,
        use_openvas=use_openvas,
        nmap_version_scan=nmap_version_scan,
        openvas_config=openvas_config,
    )

    run_full_security_scan.delay(profile.id, target_ip)
    return Response({
        'status': 'success',
        'message': f'Skenavimas {target_ip} pradėtas fone.',
        'profile_id': profile.id,
        'profile': serialize_profile(profile),
    })

@api_view(['GET'])
def get_latest_results(request, profile_id=None):
    if profile_id is None:
        profile_id = request.GET.get('profile_id')

    try:
        if profile_id:
            latest_result = ScanResult.objects.filter(profile_id=profile_id).latest('created_at')
        else:
            latest_result = ScanResult.objects.exclude(report_data={}).latest('created_at')

        return Response({'results': [serialize_result(latest_result)]})
    except ObjectDoesNotExist:
        return Response({'results': [], 'message': 'Skenavimas vykdomas arba duomenų nėra...'}, status=200)

@api_view(['GET'])
def get_profile_results(request, profile_id):
    results = ScanResult.objects.filter(profile_id=profile_id).order_by('-created_at')
    return Response({'results': [serialize_result(result) for result in results]})

@api_view(['GET'])
def get_all_results(request):
    results = ScanResult.objects.select_related('profile').order_by('-created_at')[:50]
    return Response({'results': [serialize_result(r) for r in results]})

@api_view(['POST'])
def stop_scan(request, result_id):
    try:
        result = ScanResult.objects.get(id=result_id)
    except ScanResult.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    if result.report_data.get('scan_status') != 'running':
        return Response({'error': 'Scan is not running'}, status=400)
    result.report_data['stop_requested'] = True
    result.save(update_fields=['report_data'])
    return Response({'status': 'stop requested'})


@api_view(['POST'])
def cancel_schedule(request, profile_id):
    try:
        profile = ScanProfile.objects.get(id=profile_id)
    except ScanProfile.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    profile.schedule = 'none'
    profile.next_run_at = None
    profile.save(update_fields=['schedule', 'next_run_at'])
    return Response({'status': 'schedule cancelled'})


@api_view(['DELETE'])
def delete_profile(request, profile_id):
    try:
        ScanProfile.objects.get(id=profile_id).delete()
    except ScanProfile.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    return Response({'status': 'deleted'})


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    email = request.data.get('email', '').strip()
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'status': 'ok'})  # Don't reveal if email exists

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    reset_url = f"{settings.FRONTEND_URL}?reset_uid={uid}&reset_token={token}"
    return Response({'status': 'ok', 'reset_url': reset_url})


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm(request):
    uid = request.data.get('uid')
    token = request.data.get('token')
    new_password = request.data.get('password')

    if not all([uid, token, new_password]):
        return Response({'error': 'Trūksta duomenų'}, status=400)

    try:
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
    except (User.DoesNotExist, ValueError):
        return Response({'error': 'Neteisingas UID'}, status=400)

    if not default_token_generator.check_token(user, token):
        return Response({'error': 'Neteisingas arba pasibaigęs tokenas'}, status=400)

    user.set_password(new_password)
    user.save()
    return Response({'status': 'ok'})


@api_view(['GET', 'POST'])
def user_profile(request):
    user = request.user
    if request.method == 'GET':
        return Response({'username': user.username, 'email': user.email})
    email = request.data.get('email', '').strip()
    user.email = email
    user.save(update_fields=['email'])
    return Response({'status': 'ok', 'email': user.email})
