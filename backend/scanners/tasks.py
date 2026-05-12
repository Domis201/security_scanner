import os
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import timedelta
from celery import shared_task
from celery.utils.log import get_task_logger
import nmap
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMPv226
from .models import ScanProfile, ScanResult

logger = get_task_logger(__name__)



def _xml_root(xml_string):
    return ET.fromstring(xml_string)


def _local_name(element):
    return element.tag.split('}')[-1] if '}' in element.tag else element.tag


def _find_first_id(root, tag_names):
    # Check root element itself first (create_*_response pattern)
    if 'id' in root.attrib:
        return root.attrib['id']
    for element in root.iter():
        if _local_name(element) in tag_names and 'id' in element.attrib:
            return element.attrib['id']
    return None


def _find_id_by_name(root, tag_name, name_value):
    for element in root.iter():
        if _local_name(element) == tag_name:
            name_element = next((child for child in element if _local_name(child) == 'name'), None)
            if name_element is not None and name_element.text == name_value:
                return element.attrib.get('id')
    return None


def _find_text(element, *tag_path):
    """Walk tag_path using local-name matching, return .text or None."""
    current = element
    for tag in tag_path:
        found = next((c for c in current if _local_name(c) == tag), None)
        if found is None:
            return None
        current = found
    return current.text


def _iter_tag(root, tag):
    """Iterate all descendants whose local name equals tag."""
    for elem in root.iter():
        if _local_name(elem) == tag:
            yield elem


def _run_openvas_scan(hosts, open_ports, scan_result=None, intensity='medium', openvas_config='base'):
    if not open_ports:
        return {'status': 'skipped', 'message': 'No open ports found, OpenVAS scan skipped.', 'vulnerabilities': []}

    openvas_address = os.environ.get('OPENVAS_ADDRESS', 'scanner_openvas')
    openvas_user = os.environ.get('OPENVAS_USER', 'admin')
    openvas_password = os.environ.get('OPENVAS_PASSWORD', 'tavo_saugu_slaptazodis')

    try:
        connection = TLSConnection(hostname=openvas_address, port=9390, timeout=60)
        with GMPv226(connection) as gmp:
            # context manager already connects — no gmp.connect() needed
            gmp.authenticate(openvas_user, openvas_password)

            config_root = _xml_root(gmp.get_scan_configs(details=True))
            config_name_map = {'base': 'Base', 'discovery': 'Discovery', 'full_and_fast': 'Full and fast'}
            config_name = config_name_map.get(openvas_config, 'Base')
            config_id = _find_id_by_name(config_root, 'config', config_name)
            if not config_id:
                config_id = _find_id_by_name(config_root, 'config', 'Full and fast')
            if not config_id:
                config_id = _find_first_id(config_root, ['config', 'scan_config'])
            if not config_id:
                return {'status': 'error', 'message': 'OpenVAS scan configuration not found.'}

            # Pick the OpenVAS Default scanner, not the CVE scanner
            scanner_root = _xml_root(gmp.get_scanners(details=True))
            scanner_id = _find_id_by_name(scanner_root, 'scanner', 'OpenVAS Default')
            if not scanner_id:
                # fallback: first scanner whose type != 3 (CVE scanner)
                for sc in _iter_tag(scanner_root, 'scanner'):
                    sc_type = next((c.text for c in sc if _local_name(c) == 'type'), None)
                    if sc_type != '3' and 'id' in sc.attrib:
                        scanner_id = sc.attrib['id']
                        break
            if not scanner_id:
                return {'status': 'error', 'message': 'No OpenVAS scanner available.'}

            port_range = ','.join(str(port) for port in sorted(set(open_ports)))
            port_list_xml = _xml_root(gmp.create_port_list(name=f'nmap-openports-{int(time.time())}', port_range=port_range))
            port_list_id = _find_first_id(port_list_xml, ['port_list'])
            if not port_list_id:
                return {'status': 'error', 'message': 'Could not create OpenVAS port list.'}

            target_xml = _xml_root(
                gmp.create_target(
                    name=f'OpenVAS target {hosts[0]} {int(time.time())}',
                    hosts=hosts,
                    port_list_id=port_list_id,
                )
            )
            target_id = _find_first_id(target_xml, ['target'])
            if not target_id:
                return {'status': 'error', 'message': 'Could not create OpenVAS target.'}

            task_xml = _xml_root(
                gmp.create_task(
                    name=f'OpenVAS scan for {hosts[0]}',
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id,
                    preferences={'scanner_plugins_timeout': '10', 'max_checks': '10'},
                )
            )
            task_id = _find_first_id(task_xml, ['task'])
            if not task_id:
                return {'status': 'error', 'message': 'Could not create OpenVAS task.'}

            gmp.start_task(task_id=task_id)

            # Store task_id in DB so it can be stopped externally
            if scan_result is not None:
                scan_result.report_data['openvas_task_id'] = task_id
                scan_result.save(update_fields=['report_data'])

            # Poll until done; max 10 min then force stop
            status = 'Running'
            report_id = None
            max_polls = 360  # 360 × 5s = 30 min
            poll_count = 0
            while status not in ['Done', 'Stopped', 'Interrupted']:
                time.sleep(5)
                poll_count += 1
                task_status_xml = _xml_root(gmp.get_task(task_id))

                for elem in _iter_tag(task_status_xml, 'status'):
                    status = elem.text or status
                    break

                for last_report in _iter_tag(task_status_xml, 'last_report'):
                    report_id = _find_first_id(last_report, ['report'])
                    break

                if status in ['Done', 'Stopped', 'Interrupted']:
                    break

                # Update progress and check stop flag — refresh first to avoid overwriting stop_requested
                if scan_result is not None:
                    try:
                        from django.db import connection
                        connection.close()
                        fresh = ScanResult.objects.get(id=scan_result.id)

                        # Check stop flag
                        if fresh.report_data.get('stop_requested'):
                            gmp.stop_task(task_id=task_id)
                            time.sleep(2)
                            break

                        # Update progress on fresh copy
                        progress_xml = _xml_root(gmp.get_task(task_id))
                        for prog in _iter_tag(progress_xml, 'progress'):
                            fresh.report_data['openvas_progress'] = int(prog.text or 0)
                            fresh.save(update_fields=['report_data'])
                            scan_result.report_data = fresh.report_data
                            break
                    except Exception:
                        pass

                if poll_count >= max_polls:
                    gmp.stop_task(task_id=task_id)
                    time.sleep(10)
                    break

            if not report_id:
                # Fallback: query reports filtered by task_id
                try:
                    reports_xml = _xml_root(gmp.get_reports(filter_string=f'task_id={task_id}'))
                    report_id = _find_first_id(reports_xml, ['report'])
                except Exception:
                    pass

            if not report_id:
                return {'status': 'error', 'message': 'OpenVAS scan completed but no report found.'}

            # Find the XML report format UUID dynamically
            try:
                formats_xml = _xml_root(gmp.get_report_formats())
                xml_format_id = _find_id_by_name(formats_xml, 'report_format', 'XML')
            except Exception:
                xml_format_id = None

            if xml_format_id:
                report_xml_data = gmp.get_report(report_id, report_format_id=xml_format_id)
            else:
                report_xml_data = gmp.get_report(report_id)

            report_root = _xml_root(report_xml_data)

            # Parse vulnerabilities using local-name-aware iteration
            vulnerabilities = []
            for result_elem in _iter_tag(report_root, 'result'):
                nvt_name = _find_text(result_elem, 'name')
                if not nvt_name:
                    for nvt in _iter_tag(result_elem, 'nvt'):
                        nvt_name = _find_text(nvt, 'name')
                        break

                severity_text = None
                for sev in _iter_tag(result_elem, 'severity'):
                    severity_text = sev.text
                    break

                port = _find_text(result_elem, 'port') or ''

                cves = []
                for ref in _iter_tag(result_elem, 'ref'):
                    if ref.attrib.get('type', '').lower() == 'cve':
                        cve_id = ref.attrib.get('id', '')
                        if cve_id:
                            cves.append(cve_id)

                if nvt_name:
                    try:
                        severity = float(severity_text) if severity_text else 0.0
                    except ValueError:
                        severity = 0.0
                    vulnerabilities.append({
                        'name': nvt_name,
                        'severity': severity,
                        'port': port,
                        'cves': cves,
                    })

            return {
                'status': status,
                'task_id': task_id,
                'report_id': report_id,
                'vulnerabilities': vulnerabilities,
            }

    except Exception as exc:
        print(f'OpenVAS scan failed (non-blocking): {exc}')
        return {'status': 'skipped', 'message': f'OpenVAS not available: {exc}', 'vulnerabilities': []}


@shared_task(bind=True)
def run_full_security_scan(self, profile_id, target):
    profile = ScanProfile.objects.get(id=profile_id)

    from django.utils import timezone as tz
    started_at = tz.now().isoformat()

    # Create result immediately so frontend shows scan started
    scan_result = ScanResult.objects.create(
        profile=profile,
        report_data={
            'target': target,
            'hosts': [],
            'openvas': {'status': 'pending', 'vulnerabilities': []},
            'openvas_progress': 0,
            'scan_status': 'running',
            'stage': 'nmap',
            'started_at': started_at,
        },
    )

    self.update_state(state='PROGRESS', meta={'percent': 10, 'status': 'Nmap paleidžiamas...'})

    nm = nmap.PortScanner()
    nmap_args = ['-Pn', '-T4', '-F', '--host-timeout', '60s']
    if profile.nmap_version_scan:
        nmap_args.append('-sV')
    nmap_proc = subprocess.Popen(
        ['nmap'] + nmap_args + ['-oX', '-', target],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    scan_result.report_data['nmap_pid'] = nmap_proc.pid
    scan_result.save(update_fields=['report_data'])

    while nmap_proc.poll() is None:
        time.sleep(3)
        try:
            from django.db import connection as db_conn
            db_conn.close()
            fresh = ScanResult.objects.get(id=scan_result.id)
            if fresh.report_data.get('stop_requested'):
                nmap_proc.kill()
                scan_result.report_data['scan_status'] = 'stopped'
                scan_result.save(update_fields=['report_data'])
                return 'Sustabdyta nmap fazėje.'
        except Exception:
            pass

    xml_output, _ = nmap_proc.communicate()
    nm.analyse_nmap_xml_scan(xml_output.decode('utf-8', errors='ignore'))

    hosts_report = []
    all_open_ports = []
    all_hosts = nm.all_hosts()

    for host in all_hosts:
        host_ports = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                port_item = {
                    'port': port,
                    'service': service.get('name', 'unknown'),
                    'state': service.get('state', 'unknown'),
                    'version': service.get('version', ''),
                    'vulnerability': 'Atviras portas' if service.get('state') == 'open' else 'Saugus',
                }
                host_ports.append(port_item)
                if service.get('state') == 'open':
                    all_open_ports.append(port)

        hosts_report.append({
            'ip': host,
            'ports': host_ports,
            'open_port_count': sum(1 for p in host_ports if p['state'] == 'open'),
            'open_ports': [p['port'] for p in host_ports if p['state'] == 'open'],
        })

    if not hosts_report:
        hosts_report.append({
            'ip': target,
            'ports': [],
            'open_port_count': 0,
            'open_ports': [],
        })

    # Update with nmap results
    scan_result.report_data.update({
        'hosts': hosts_report,
        'stage': 'openvas',
    })
    scan_result.save(update_fields=['report_data'])

    # Check stop flag before starting OpenVAS
    scan_result.refresh_from_db()
    if scan_result.report_data.get('stop_requested'):
        scan_result.report_data['scan_status'] = 'stopped'
        scan_result.save(update_fields=['report_data'])
        return 'Skenavimas sustabdytas.'

    if not profile.use_openvas:
        scan_result.report_data.update({
            'openvas': {'status': 'skipped', 'message': 'OpenVAS išjungtas.', 'vulnerabilities': []},
            'openvas_progress': 100,
            'scan_status': 'completed',
        })
        scan_result.save(update_fields=['report_data'])
        return f'Skenavimas baigtas (tik Nmap). Rasta portų: {len(all_open_ports)}'

    try:
        openvas_status = _run_openvas_scan(
            [host['ip'] for host in hosts_report if host.get('open_port_count', 0) > 0], all_open_ports,
            scan_result=scan_result, intensity=profile.intensity,
            openvas_config=profile.openvas_config,
        )
    except Exception as e:
        print(f'OpenVAS scan error (non-blocking): {e}')
        openvas_status = {'status': 'skipped', 'message': 'OpenVAS unavailable', 'vulnerabilities': []}

    if 'vulnerabilities' not in openvas_status:
        openvas_status['vulnerabilities'] = []

    scan_result.refresh_from_db()
    final_status = 'stopped' if scan_result.report_data.get('stop_requested') else 'completed'
    completed_at = tz.now().isoformat()
    started = scan_result.report_data.get('started_at', scan_result.created_at.isoformat())
    from datetime import datetime
    try:
        delta = datetime.fromisoformat(completed_at) - datetime.fromisoformat(started)
        duration = int(delta.total_seconds())
    except Exception:
        duration = None
    scan_result.report_data.update({
        'openvas': openvas_status,
        'openvas_progress': 100,
        'scan_status': final_status,
        'completed_at': completed_at,
        'duration_seconds': duration,
    })
    scan_result.save(update_fields=['report_data'])

    return f'Skenavimas baigtas. Rasta portų: {len(all_open_ports)}'


def _next_run(profile, now):
    from zoneinfo import ZoneInfo
    tz = ZoneInfo('Europe/Vilnius')
    local_now = now.astimezone(tz)
    h, m = map(int, profile.schedule_time.split(':'))

    if profile.schedule == 'hourly':
        next_dt = local_now.replace(minute=m, second=0, microsecond=0)
        if next_dt <= local_now:
            next_dt += timedelta(hours=1)
    elif profile.schedule == 'daily':
        next_dt = local_now.replace(hour=h, minute=m, second=0, microsecond=0)
        if next_dt <= local_now:
            next_dt += timedelta(days=1)
    elif profile.schedule == 'weekly':
        days_ahead = (profile.schedule_weekday - local_now.weekday()) % 7
        next_dt = local_now.replace(hour=h, minute=m, second=0, microsecond=0) + timedelta(days=days_ahead)
        if next_dt <= local_now:
            next_dt += timedelta(weeks=1)
    else:
        return None
    from datetime import timezone as dt_timezone
    return next_dt.astimezone(ZoneInfo('UTC')).replace(tzinfo=dt_timezone.utc)


@shared_task
def run_scheduled_scans():
    from django.utils import timezone
    now = timezone.now()
    profiles = ScanProfile.objects.exclude(schedule='none')
    for profile in profiles:
        if profile.next_run_at and profile.next_run_at > now:
            continue
        run_full_security_scan.delay(profile.id, profile.target_ip)
        profile.next_run_at = _next_run(profile, now)
        profile.save(update_fields=['next_run_at'])
        logger.info(f'Scheduled scan started for profile {profile.id} ({profile.target_ip})')
