# fir_method_extension/views.py
import json
import logging
import re
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.contrib.auth.models import User
from django.conf import settings  
from incidents.models import Incident, IncidentStatus, SeverityChoice, IncidentCategory, Tlp, Label, LabelGroup
from fir_method_extension.models import MethodIncidentData
from fir_artifacts.models import Artifact
from crum import set_current_user


from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count, Q
from datetime import timedelta
import sys

from django.shortcuts import  redirect, get_object_or_404, reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import  PlaybookStepExecution


from django.http import HttpResponse
import csv
from datetime import datetime


logger = logging.getLogger(__name__)

SOURCE_NORMALIZATION = {
    'wazuh': {'name': 'Wazuh SIEM', 'priority_field': 'rule.level'},
    'suricata': {'name': 'Suricata IDS', 'priority_field': 'priority'},
    'ossec': {'name': 'OSSEC HIDS', 'priority_field': 'rule.level'},
    'generic': {'name': 'Generic Webhook', 'priority_field': 'severity'},
}


def normalize_severity(source: str, raw_value) -> str:
    source_cfg = SOURCE_NORMALIZATION.get(source, SOURCE_NORMALIZATION['generic'])
    
    if source == 'wazuh':
        level = int(raw_value) if str(raw_value).isdigit() else 0
        if level >= 15: return 'critical'
        elif level >= 10: return 'high'
        elif level >= 5: return 'medium'
        return 'low'
    elif source == 'suricata':
        priority = int(raw_value) if str(raw_value).isdigit() else 3
        if priority == 1: return 'high'
        elif priority <= 3: return 'medium'
        return 'low'
    

    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
    return severity_map.get(str(raw_value).lower(), 'medium')


def parse_and_create_artifacts(incident, text):

    patterns = {
        'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'domain': r'\b(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }

    for art_type, regex in patterns.items():
        matches = set(re.findall(regex, text))
        for value in matches:
            
            if art_type == 'domain' and len(value) < 4:
                continue
            artifact, _ = Artifact.objects.get_or_create(type=art_type, value=value)
            incident.artifacts.add(artifact)


@csrf_exempt
@require_http_methods(["POST"])
def siem_ingest_api(request):

    token = request.headers.get("X-FIR-API-Token")
    expected_token = getattr(settings, 'SIEM_WEBHOOK_TOKEN', 'dev-token-change-me')
    if token != expected_token:
        logger.warning(f"Invalid token attempt from {request.META.get('REMOTE_ADDR')}")
        return JsonResponse({"error": "Invalid token"}, status=403)


    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    try:

        raw_severity = payload.get("severity", "medium")
        source = payload.get("source", "generic")
        normalized_sev = normalize_severity(source, raw_severity)
        
        severity_map = {"critical": "1", "high": "2", "medium": "3", "low": "4", "info": "4"}
        sev_level = severity_map.get(normalized_sev, "3")
        severity_obj = SeverityChoice.objects.filter(name=str(sev_level)).first()
        if not severity_obj:
            severity_obj = SeverityChoice.objects.first()
            if not severity_obj:
                return JsonResponse({"error": "No severity levels configured"}, status=400)

        status_obj = (
            IncidentStatus.objects.filter(name__iexact="new").first() or
            IncidentStatus.objects.filter(name__iexact="open").first() or
            IncidentStatus.objects.filter(name__in=["New", "Open", "Triage", "Triaged"]).first() or
            IncidentStatus.objects.first()
        )
        if not status_obj:
            return JsonResponse({"error": "No valid incident status found"}, status=400)

    
        category_id = payload.get("category_id")
        category_obj = IncidentCategory.objects.filter(id=category_id).first() if category_id else None
        category_obj = category_obj or IncidentCategory.objects.first()
        if not category_obj:
            return JsonResponse({"error": "No categories found in database"}, status=400)

        tlp_obj = Tlp.objects.filter(name__iexact="white").first() or Tlp.objects.first()
        if not tlp_obj:
            return JsonResponse({"error": "No TLP values found"}, status=400)

        
        detection_obj = Label.objects.filter(group__name="detection").first()
        if not detection_obj:
            detection_group, _ = LabelGroup.objects.get_or_create(name="detection")
            detection_obj, _ = Label.objects.get_or_create(name="Automated", group=detection_group)

        
        sys_user, _ = User.objects.get_or_create(
            username="siem_importer",
            defaults={"is_active": True, "email": "siem@local", "first_name": "SIEM", "last_name": "Importer"}
        )

        
        set_current_user(sys_user)

        try:
           
            incident = Incident.objects.create(
                subject=payload.get("title", "SIEM Alert")[:256],
                description=payload.get("description", "No description provided."),
                category=category_obj,
                status=status_obj,
                opened_by=sys_user,
                severity=severity_obj,
                tlp=tlp_obj,
                detection=detection_obj,
                is_incident=True,
                date=timezone.now()
            )

            method_data, _ = MethodIncidentData.objects.get_or_create(incident=incident)
            method_data.phase1_started = timezone.now()
            method_data.assigned_role = 'l1_monitoring'  
            method_data.role_assigned_at = timezone.now()
            method_data.save()

            playbook_name = payload.get('playbook_name')
            if playbook_name:
                try:
                    from fir_method_extension.models import Playbook, PlaybookStepExecution
                    playbook = Playbook.objects.get(name=playbook_name, is_active=True)
                    method_data.applied_playbook = playbook
                    method_data.save()
                    
                    for step in playbook.steps.all():
                        PlaybookStepExecution.objects.get_or_create(
                            incident_data=method_data,
                            step=step,
                            defaults={'status': 'pending'}
                        )
                    logger.info(f"Playbook '{playbook_name}' assigned to incident {incident.id}")
                except Playbook.DoesNotExist:
                    logger.warning(f"Playbook '{playbook_name}' not found for incident {incident.id}")
                except Exception as e:
                    logger.error(f"Error assigning playbook to incident {incident.id}: {e}")
                    
            parse_and_create_artifacts(incident, payload.get("description", ""))

            logger.info(f" SIEM alert ingested: Incident #{incident.id} from {source}")
            return JsonResponse({"status": "created", "incident_id": incident.id}, status=201)

        finally:
            set_current_user(None) 

    except Exception as e:
        set_current_user(None)
        logger.error(f"Error processing SIEM alert: {e}", exc_info=True)
        return JsonResponse({"error": f"Internal error: {str(e)}"}, status=500)
    







logger = logging.getLogger(__name__)

@staff_member_required
def ir_dashboard(request):
    
    import sys
    print("--- DASHBOARD START ---", file=sys.stderr)
    
    now = timezone.now()
    
    all_data = MethodIncidentData.objects.all()
    total_records = all_data.count()
    print(f"TOTAL RECORDS IN DB: {total_records}", file=sys.stderr)


    p1 = all_data.filter(phase1_started__isnull=False, phase2_started__isnull=True).count()
    p2 = all_data.filter(phase2_started__isnull=False, phase3_started__isnull=True).count()
    p3 = all_data.filter(phase3_started__isnull=False, phase4_started__isnull=True).count()
    p4 = all_data.filter(phase4_started__isnull=False, phase4_completed__isnull=True).count()
    closed = all_data.filter(phase4_completed__isnull=False).count()
    
    print(f"PHASE COUNTS: P1={p1}, P2={p2}, P3={p3}, P4={p4}, CLOSED={closed}", file=sys.stderr)
    
    total_active = p1 + p2 + p3 + p4
    
    phase_chart_data = []
    colors = ['#495057', '#6c757d', '#868e96', '#343a40']
    labels = ['Analysis', 'Containment', 'Recovery', 'Post-incident']
    
    for i, count in enumerate([p1, p2, p3, p4]):
        percent = (count / total_active * 100) if total_active > 0 else 0
        phase_chart_data.append({
            'label': labels[i],
            'count': count,
            'percent': round(percent, 1),
            'color': colors[i]
        })


    active_qs = all_data.filter(phase4_completed__isnull=True)
    sla_total = active_qs.count()
    sla_br = active_qs.filter(sla_breached=True).count()
    sla_comp = sla_total - sla_br
    
    sla_pct = (sla_comp / sla_total * 100) if sla_total > 0 else 100
    sla_br_pct = (sla_br / sla_total * 100) if sla_total > 0 else 0
    
    print(f"SLA: Total={sla_total}, Breached={sla_br}, Comp%={sla_pct}", file=sys.stderr)


    role_data = []
    roles = all_data.values('assigned_role').annotate(cnt=Count('id')).order_by('-cnt')
    max_role = max([r['cnt'] for r in roles], default=1)
    
    for r in roles:
        label = dict(MethodIncidentData.ROLE_CHOICES).get(r['assigned_role'], r['assigned_role'] or 'None')
        role_data.append({
            'label': label[:20],
            'count': r['cnt'],
            'width': (r['cnt'] / max_role * 100)
        })

    daily = [{'day': 'Today', 'count': total_active, 'width': 50}]

    context = {
        'phase_stats': {'phase1': p1, 'phase2': p2, 'phase3': p3, 'phase4': p4, 'closed': closed},
        'total_active': total_active,
        'phase_chart_data': phase_chart_data,
        'sla_compliance_pct': round(sla_pct, 1),
        'sla_breached_pct': round(sla_br_pct, 1),
        'sla_compliant': sla_comp,
        'sla_total_active': sla_total,
        'sla_breached': sla_br,
        'sla_compliance_good': sla_pct >= 90,
        'recent_escalations': 0, 
        'role_chart_data': role_data,
        'phase_avg': {'phase1': '-', 'phase2': '-', 'phase3': '-', 'phase4': '-'},
        'daily_stats': daily
    }
    
    print("--- DASHBOARD END (Context prepared) ---", file=sys.stderr)
    sys.stderr.flush()
    
    return render(request, 'fir_method_extension/ir_dashboard.html', context)













@login_required
def ir_queue(request):

    user = request.user
    is_l1 = user.groups.filter(name='L1-Analysts').exists() or user.is_staff
    is_l2 = user.groups.filter(name='L2-Analysts').exists() or user.is_superuser

    base_qs = MethodIncidentData.objects.select_related('incident', 'assigned_to', 'accepted_by')

    if is_l1 and not is_l2:
        qs = base_qs.filter(Q(assigned_role='l1_monitoring') | Q(accepted_by__isnull=True))
    elif is_l2:
        qs = base_qs.filter(Q(assigned_role__in=['l1_monitoring', 'l2_monitoring']) | Q(escalated_to_l2=True))
    else:
        qs = base_qs

    qs = qs.order_by('-incident__date')

    context = {
        'incidents': qs,
        'title': 'IR Queue'
    }
    return render(request, 'fir_method_extension/ir/queue.html', context)



@login_required
def ir_incident_detail(request, incident_id):

    md = get_object_or_404(
        MethodIncidentData.objects.select_related(
            'incident', 'assigned_to', 'applied_playbook', 'accepted_by'
        ),
        incident__id=incident_id
    )
    
    steps = []
    if md.applied_playbook:
        step_qs = md.applied_playbook.steps.all().order_by('order')
        for step in step_qs:
           
            exec_record, created = PlaybookStepExecution.objects.get_or_create(
                incident_data=md,
                step=step,
                defaults={'status': 'pending'}
            )
            
            if exec_record:
                status = exec_record.status
                notes = exec_record.notes
                executed_by = exec_record.executed_by
                executed_at = exec_record.executed_at
                execution_id = exec_record.id
            else:
                status = 'pending'
                notes = ''
                executed_by = None
                executed_at = None
                execution_id = None
                
            steps.append({
                'step': step,
                'status': status,
                'notes': notes,
                'executed_by': executed_by,
                'executed_at': executed_at,
                'execution_id': execution_id
            })

    context = {
        'md': md,
        'steps': steps,
        'title': f'Incident #{md.incident.id} Workspace'
    }
    return render(request, 'fir_method_extension/ir/incident_detail.html', context)


@login_required
def accept_incident_action(request, incident_id):
    
    if request.method != 'POST':
        
        return redirect('fir_method_extension:ir_queue')
    

    md = get_object_or_404(MethodIncidentData, incident__id=incident_id)
    
    if md.accepted_at:
        messages.warning(request, 'Incident already accepted')
        
        return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)

    #from incidents.models import IncidentStatus
    open_status = IncidentStatus.objects.filter(name__iexact='open').first() or IncidentStatus.objects.first()
    
    md.accepted_at = timezone.now()
    md.accepted_by = request.user
    md.assigned_role = 'l1_monitoring'
    md.assigned_to = request.user
    md.role_assigned_at = timezone.now()
    if open_status:
        md.incident.status = open_status
        md.incident.save()

    if md.incident.category and not md.applied_playbook:
        from .models import Playbook
        playbook = Playbook.objects.filter(
            category=md.incident.category,
            phase=md.get_current_phase() or 1,
            is_active=True
        ).first()
        if playbook:
            md.applied_playbook = playbook
            md.playbook_started_at = timezone.now()
            md.playbook_used = playbook.name[:150]

    md.save()
    messages.success(request, f'Incident #{incident_id} accepted into work')

    return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)


@login_required
def complete_step_action(request, step_execution_id):
    
    if request.method != 'POST':
        return redirect('fir_method_extension:ir_queue')

    exec_record = get_object_or_404(PlaybookStepExecution, id=step_execution_id)
    

    md = exec_record.incident_data
    if md.assigned_to != request.user and not request.user.is_staff:
        messages.error(request, 'You do not have permission to update this step')
        return redirect('fir_method_extension:ir_incident_detail', incident_id=md.incident_id)

    exec_record.status = request.POST.get('status', 'completed')
    exec_record.notes = request.POST.get('notes', exec_record.notes)
    exec_record.executed_by = request.user
    exec_record.executed_at = timezone.now()
    exec_record.save()

    messages.success(request, f'Step updated: {exec_record.status}')
    return redirect('fir_method_extension:ir_incident_detail', incident_id=md.incident_id)



@login_required
def save_analyst_notes(request, incident_id):
    if request.method != 'POST':
        return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)
    
    md = get_object_or_404(MethodIncidentData, incident__id=incident_id)
    

    if md.assigned_to != request.user and not request.user.is_staff:
        messages.error(request, 'You do not have permission to update notes for this incident')
        return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)
    
    notes = request.POST.get('analyst_notes', '')
    md.analyst_notes = notes
    md.notes_updated_at = timezone.now()
    md.save()
    
    messages.success(request, 'Notes saved successfully')
    return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)


@login_required
def export_incident_report(request, incident_id, format='csv'):
    md = get_object_or_404(
        MethodIncidentData.objects.select_related(
            'incident', 'assigned_to', 'accepted_by', 'applied_playbook'
        ),
        incident__id=incident_id
    )
    
    report_data = {
        'incident_id': md.incident.id,
        'subject': md.incident.subject,
        'description': md.incident.description,
        'category': md.incident.category.name if md.incident.category else 'N/A',
        'severity': md.incident.severity.name if md.incident.severity else 'N/A',
        'status': md.incident.status.name,
        'created_at': md.incident.date.strftime('%Y-%m-%d %H:%M:%S'),
        'accepted_by': md.accepted_by.username if md.accepted_by else 'N/A',
        'accepted_at': md.accepted_at.strftime('%Y-%m-%d %H:%M:%S') if md.accepted_at else 'N/A',
        'assigned_role': md.get_assigned_role_display(),
        'assigned_to': md.assigned_to.username if md.assigned_to else 'N/A',
        'current_phase': md.get_current_phase(),
        'analyst_notes': md.analyst_notes,
        'sla_breached': 'Yes' if md.sla_breached else 'No',
        'playbook_name': md.applied_playbook.name if md.applied_playbook else 'N/A',
        'playbook_version': md.applied_playbook.version if md.applied_playbook else 'N/A',
    }
    

    steps_data = []
    if md.applied_playbook:
        for step in md.applied_playbook.steps.all().order_by('order'):
            exec_record = PlaybookStepExecution.objects.filter(
                incident_data=md, step=step
            ).first()
            steps_data.append({
                'order': step.order,
                'title': step.title,
                'instruction': step.instruction,
                'status': exec_record.status if exec_record else 'pending',
                'executed_by': exec_record.executed_by.username if exec_record and exec_record.executed_by else 'N/A',
                'executed_at': exec_record.executed_at.strftime('%Y-%m-%d %H:%M:%S') if exec_record and exec_record.executed_at else 'N/A',
                'notes': exec_record.notes if exec_record else '',
            })
    

    transitions = md.get_phase_transition_log()
    
    if format == 'csv':
        return _export_report_csv(report_data, steps_data, transitions)
    else:
        return _export_report_html(report_data, steps_data, transitions)


def _export_report_csv(report_data, steps_data, transitions):
    """Generate CSV report"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="incident_{report_data["incident_id"]}_report.csv"'
    
    writer = csv.writer(response)
    
    writer.writerow(['INCIDENT REPORT'])
    writer.writerow(['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    

    writer.writerow(['INCIDENT DETAILS'])
    for key, label in [
        ('incident_id', 'ID'), ('subject', 'Subject'), ('category', 'Category'),
        ('severity', 'Severity'), ('status', 'Status'), ('created_at', 'Created At'),
        ('accepted_by', 'Accepted By'), ('accepted_at', 'Accepted At'),
        ('assigned_role', 'Assigned Role'), ('assigned_to', 'Assigned To'),
        ('current_phase', 'Current Phase'), ('sla_breached', 'SLA Breached'),
        ('playbook_name', 'Playbook'), ('playbook_version', 'Playbook Version'),
    ]:
        writer.writerow([label, report_data.get(key, 'N/A')])
    
    writer.writerow([])
    writer.writerow(['ANALYST NOTES'])
    writer.writerow([report_data.get('analyst_notes', '')])
    
    writer.writerow([])
    writer.writerow(['PLAYBOOK STEPS'])
    writer.writerow(['Order', 'Title', 'Instruction', 'Status', 'Executed By', 'Executed At', 'Notes'])
    for step in steps_data:
        writer.writerow([
            step['order'], step['title'], step['instruction'],
            step['status'], step['executed_by'], step['executed_at'], step['notes']
        ])
    
    writer.writerow([])
    writer.writerow(['PHASE TRANSITIONS'])
    writer.writerow(['Event', 'Timestamp'])
    for t in transitions:
        writer.writerow([t['label'], t['timestamp'].strftime('%Y-%m-%d %H:%M:%S')])
    
    return response


def _export_report_html(report_data, steps_data, transitions):
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Incident #{report_data["incident_id"]} Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1, h2 {{ color: #2c3e50; }}
            table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background: #f5f5f5; }}
            .section {{ margin: 24px 0; }}
            .notes {{ background: #f9f9f9; padding: 12px; border-left: 4px solid #2196F3; white-space: pre-wrap; }}
            .step-completed {{ background: #d4edda; }}
            .step-pending {{ background: #fff3cd; }}
            .step-failed {{ background: #f8d7da; }}
            @media print {{ body {{ margin: 20px; }} }}
        </style>
    </head>
    <body>
        <h1>Incident Response Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="section">
            <h2>Incident Details</h2>
            <table>
                <tr><th>ID</th><td>{report_data["incident_id"]}</td></tr>
                <tr><th>Subject</th><td>{report_data["subject"]}</td></tr>
                <tr><th>Category</th><td>{report_data["category"]}</td></tr>
                <tr><th>Severity</th><td>{report_data["severity"]}</td></tr>
                <tr><th>Status</th><td>{report_data["status"]}</td></tr>
                <tr><th>Created</th><td>{report_data["created_at"]}</td></tr>
                <tr><th>Accepted By</th><td>{report_data["accepted_by"]} at {report_data["accepted_at"]}</td></tr>
                <tr><th>Assigned Role</th><td>{report_data["assigned_role"]}</td></tr>
                <tr><th>Assigned To</th><td>{report_data["assigned_to"]}</td></tr>
                <tr><th>Current Phase</th><td>{report_data["current_phase"]}</td></tr>
                <tr><th>SLA Breached</th><td>{report_data["sla_breached"]}</td></tr>
                <tr><th>Playbook</th><td>{report_data["playbook_name"]} (v{report_data["playbook_version"]})</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Analyst Notes</h2>
            <div class="notes">{report_data["analyst_notes"] or "No notes added."}</div>
        </div>
        
        <div class="section">
            <h2>Playbook Steps Execution</h2>
            <table>
                <thead>
                    <tr><th>Step</th><th>Title</th><th>Status</th><th>Executed By</th><th>Executed At</th><th>Notes</th></tr>
                </thead>
                <tbody>
    '''
    
    for step in steps_data:
        row_class = f'step-{step["status"]}'
        html += f'''
                    <tr class="{row_class}">
                        <td>{step["order"]}</td>
                        <td>{step["title"]}</td>
                        <td>{step["status"].title()}</td>
                        <td>{step["executed_by"]}</td>
                        <td>{step["executed_at"]}</td>
                        <td>{step["notes"]}</td>
                    </tr>
        '''
    
    html += '''
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Phase Transition Log</h2>
            <table>
                <thead><tr><th>Event</th><th>Timestamp</th></tr></thead>
                <tbody>
    '''
    
    for t in transitions:
        html += f'''
                    <tr>
                        <td>{t["label"]}</td>
                        <td>{t["timestamp"].strftime('%Y-%m-%d %H:%M:%S')}</td>
                    </tr>
        '''
    
    html += '''
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''
    
    response = HttpResponse(html, content_type='text/html')
    response['Content-Disposition'] = f'attachment; filename="incident_{report_data["incident_id"]}_report.html"'
    return response




@login_required
def update_incident_status(request, incident_id):
    if request.method != 'POST':
        return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)
    
    md = get_object_or_404(MethodIncidentData, incident__id=incident_id)
    new_status_name = request.POST.get('status', '').strip()
    
    if not new_status_name:
        messages.error(request, 'Status is required')
        return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)
    
    if md.assigned_to != request.user and not request.user.is_staff:
        messages.error(request, 'You do not have permission to change status')
        return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)
    
    #from incidents.models import IncidentStatus
    new_status = IncidentStatus.objects.filter(name__iexact=new_status_name).first()
    if not new_status:
        new_status, _ = IncidentStatus.objects.get_or_create(name=new_status_name)
    
    old_status = md.incident.status.name
    md.incident.status = new_status
    md.incident.save() 
    
    messages.success(request, f'Status changed from "{old_status}" to "{new_status_name}". Phase tracking updated.')
    return redirect('fir_method_extension:ir_incident_detail', incident_id=incident_id)
