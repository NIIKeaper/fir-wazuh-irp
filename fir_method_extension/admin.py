# /opt/fir/FIR/fir_method_extension/admin.py

from django.contrib import admin
from django.db.models import Count, Q
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from django.forms.models import BaseInlineFormSet
from .models import MethodIncidentData, Playbook, PlaybookStep, PlaybookStepExecution


class PlaybookStepExecutionInlineFormSet(BaseInlineFormSet):
    def save_new_objects(self, commit=True):
        for form in self.forms:
            if form.instance.pk and form.cleaned_data.get('status') == 'completed' and form.instance.status != 'completed':
                form.instance.executed_by = form.instance.executed_by or self.request.user
                form.instance.executed_at = form.instance.executed_at or timezone.now()
        return super().save_new_objects(commit)


class PlaybookStepExecutionInline(admin.TabularInline):
    model = PlaybookStepExecution
    formset = PlaybookStepExecutionInlineFormSet
    extra = 0
    fields = ['step', 'status', 'executed_by', 'executed_at', 'notes']
    readonly_fields = ['executed_at']
    ordering = ['step__order']

    def get_formset(self, request, obj=None, **kwargs):
        formset = super().get_formset(request, obj, **kwargs)
        if obj and obj.applied_playbook:
            formset.form.base_fields['step'].queryset = obj.applied_playbook.steps.all()
        return formset


class PlaybookStepInline(admin.TabularInline):
    model = PlaybookStep
    extra = 1
    fields = ['order', 'title', 'instruction', 'expected_outcome', 'reference_url']
    ordering = ['order']


@admin.register(Playbook)
class PlaybookAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'phase', 'version', 'is_active', 'step_count']
    list_filter = ['is_active', 'phase', 'category']
    search_fields = ['name', 'description']
    inlines = [PlaybookStepInline]

    fieldsets = (
        ('Basic Information', {'fields': ['name', 'description', 'category', 'phase']}),
        ('Metadata', {'fields': ['version', 'is_active'], 'classes': ['collapse']}),
    )

    def step_count(self, obj):
        return obj.steps.count()
    step_count.short_description = 'Steps'


@admin.register(MethodIncidentData)
class MethodIncidentDataAdmin(admin.ModelAdmin):
    list_display = [
        'incident_link', 'current_phase_badge', 'accepted_badge',
        'assigned_role_display', 'assigned_to_user', 'sla_status_badge', 'playbook_badge'
    ]
    list_filter = [
        'assigned_role', 'escalated_to_l2', 'sla_breached', 'is_false_positive',
        'applied_playbook', 'accepted_by'
    ]
    search_fields = [
        'incident__subject', 'incident__description', 'lessons_learned',
        'recommendations', 'assigned_to__username', 'applied_playbook__name'
    ]
    readonly_fields = ['incident', 'current_phase_display', 'timeline_html', 'playbook_steps_overview']
    date_hierarchy = 'incident__date'
    list_per_page = 25
    inlines = [PlaybookStepExecutionInline]

    fieldsets = (
        ('Incident', {'fields': ['incident', 'current_phase_display']}),
        ('Acceptance & Role', {
            'fields': ['accepted_at', 'accepted_by', 'assigned_role', 'assigned_to', 'role_assigned_at'],
            'classes': ['collapse']
        }),
        ('Playbook Assignment', {
            'fields': ['applied_playbook', 'playbook_started_at', 'playbook_completed_at',
                       'playbook_notes', 'playbook_steps_overview'],
            'classes': ['collapse']
        }),
        ('1. Detection & Analysis', {
            'fields': ['phase1_started', 'phase1_completed', 'is_false_positive',
                       'false_positive_reason', 'escalated_to_l2', 'l2_assigned_at'],
            'classes': ['collapse']
        }),
        ('2. Damage Containment', {
            'fields': ['phase2_started', 'phase2_completed', 'playbook_used',
                       'custom_containment_actions', 'localized_at'],
            'classes': ['collapse']
        }),
        ('3. Eradication & Recovery', {
            'fields': ['phase3_started', 'phase3_completed', 'recovery_plan',
                       'recovery_verified', 'recovered_at'],
            'classes': ['collapse']
        }),
        ('4. Post-Incident Analysis', {
            'fields': ['phase4_started', 'phase4_completed', 'lessons_learned',
                       'recommendations', 'improvements_implemented', 'closed_at'],
            'classes': ['collapse']
        }),
        ('Management & SLA', {
            'fields': ['ir_manager', 'sla_deadline', 'sla_breached', 'timeline_html'],
            'classes': ['collapse']
        }),
    )

    def incident_link(self, obj):
        url = reverse('admin:incidents_incident_change', args=[obj.incident.pk])
        return format_html('<a href="{}">{}</a>', url, obj.incident.subject[:50])
    incident_link.short_description = 'Incident'

    def current_phase_badge(self, obj):
        phase = obj.get_current_phase()
        if not phase:
            return format_html('<span style="padding:3px 8px;background:#ccc;border-radius:3px;">Not started</span>')
        colors = {1: '#2196F3', 2: '#FF9800', 3: '#4CAF50', 4: '#9C27B0'}
        labels = {1: 'Analysis', 2: 'Containment', 3: 'Recovery', 4: 'Post-incident'}
        return format_html(
            '<span style="padding:3px 10px;background:{};color:white;border-radius:3px;font-weight:500;">{}</span>',
            colors.get(phase, '#666'), labels.get(phase, f'Phase {phase}')
        )
    current_phase_badge.short_description = 'Phase'

    def accepted_badge(self, obj):
        if obj.accepted_at:
            user = obj.accepted_by.username if obj.accepted_by else 'Unknown'
            return format_html(
                '<span style="padding:3px 8px;background:#4CAF50;color:white;border-radius:3px;">Accepted by {}</span>', user
            )
        return format_html('<span style="padding:3px 8px;background:#f44336;color:white;border-radius:3px;">Pending</span>')
    accepted_badge.short_description = 'Status'

    def assigned_role_display(self, obj):
        return obj.get_assigned_role_display() or '-'
    assigned_role_display.short_description = 'Role'

    def assigned_to_user(self, obj):
        if obj.assigned_to:
            return obj.assigned_to.get_full_name() or obj.assigned_to.username
        return '-'
    assigned_to_user.short_description = 'Assigned To'

    def sla_status_badge(self, obj):
        if obj.sla_breached:
            return format_html('<span style="padding:3px 8px;background:#f44336;color:white;border-radius:3px;">BREACHED</span>')
        if obj.sla_deadline:
            return format_html('<span style="padding:3px 8px;background:#4CAF50;color:white;border-radius:3px;">OK</span>')
        return format_html('<span style="padding:3px 8px;background:#9e9e9e;color:white;border-radius:3px;">N/A</span>')
    sla_status_badge.short_description = 'SLA'

    def playbook_badge(self, obj):
        if obj.applied_playbook:
            return format_html('<span style="padding:3px 8px;background:#607D8B;color:white;border-radius:3px;">{}</span>',
                             obj.applied_playbook.name[:20])
        return format_html('<span style="padding:3px 8px;background:#ccc;color:#666;border-radius:3px;">No playbook</span>')
    playbook_badge.short_description = 'Playbook'

    def current_phase_display(self, obj):
        phase = obj.get_current_phase()
        if not phase:
            return "Incident not yet in progress"
        phase_info = {
            1: "Detection & Analysis: Alert verification, false positive check, initial assessment",
            2: "Damage Containment: Threat localization, playbook application, impact limitation",
            3: "Eradication & Recovery: Threat removal, system restoration, functionality verification",
            4: "Post-Incident Analysis: Lessons learned, recommendations, improvement implementation"
        }
        return phase_info.get(phase, f"Phase {phase}")
    current_phase_display.short_description = 'Current Phase Details'

    def timeline_html(self, obj):
        phases = [
            ('phase1_started', 'phase1_completed', '1. Analysis'),
            ('phase2_started', 'phase2_completed', '2. Containment'),
            ('phase3_started', 'phase3_completed', '3. Recovery'),
            ('phase4_started', 'phase4_completed', '4. Post-incident'),
        ]
        html = '<div style="font-family:monospace;font-size:12px;line-height:1.8;">'
        for start_field, end_field, label in phases:
            start = getattr(obj, start_field)
            end = getattr(obj, end_field)
            if start:
                status = "OK" if end else "->"
                time_str = start.strftime("%d.%m %H:%M")
                if end:
                    time_str += " - " + end.strftime("%d.%m %H:%M")
                html += f'<div>{status} <b>{label}</b>: {time_str}</div>'
        if obj.closed_at:
            html += f'<div style="margin-top:8px;border-top:1px solid #ddd;padding-top:4px;">Closed: {obj.closed_at.strftime("%d.%m.%Y %H:%M")}</div>'
        html += '</div>'
        return format_html(html)
    timeline_html.short_description = 'Timeline'

    def playbook_steps_overview(self, obj):
        if not obj.applied_playbook:
            return "No playbook assigned"
        steps = obj.applied_playbook.steps.all().order_by('order')
        if not steps:
            return "Playbook has no steps"
        html = '<div style="font-family:monospace;font-size:12px;line-height:1.6;">'
        for step in steps:
            exec_record = obj.step_executions.filter(step=step).first()
            status_icon = "✔️" if exec_record and exec_record.status == 'completed' else "○"
            html += f'<div style="margin:4px 0;">{status_icon} <b>{step.order}.</b> {step.title}</div>'
        html += '</div>'
        return format_html(html)
    playbook_steps_overview.short_description = 'Playbook Overview'

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('incident', 'assigned_to', 'ir_manager', 'applied_playbook', 'accepted_by')

    actions = ['accept_incidents', 'assign_playbook_to_selected', 'mark_phase_completed', 'export_for_report']

    def accept_incidents(self, request, queryset):
        from incidents.models import IncidentStatus
        open_status = IncidentStatus.objects.filter(name__iexact="open").first() or IncidentStatus.objects.first()
        if not open_status:
            self.message_user(request, "No valid incident status found", level='ERROR')
            return

        count = 0
        for md in queryset:
            if md.accepted_at:
                continue

            md.accepted_at = timezone.now()
            md.accepted_by = request.user
            md.assigned_role = 'l1_monitoring'
            md.assigned_to = request.user
            md.role_assigned_at = timezone.now()
            md.incident.status = open_status
            md.incident.save()

            if not md.applied_playbook and md.incident.category:
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
            count += 1
        self.message_user(request, f"Accepted {count} incidents into work")
    accept_incidents.short_description = "Accept selected incidents into work (L1)"

    def assign_playbook_to_selected(self, request, queryset):
        assigned_count = 0
        for md in queryset:
            if md.incident.category and md.get_current_phase() and not md.applied_playbook:
                playbook = Playbook.objects.filter(
                    category=md.incident.category, phase=md.get_current_phase(), is_active=True
                ).first()
                if playbook:
                    md.applied_playbook = playbook
                    md.playbook_started_at = md.playbook_started_at or timezone.now()
                    md.playbook_used = playbook.name[:150]
                    md.save()
                    assigned_count += 1
        self.message_user(request, f"Assigned playbooks to {assigned_count} incidents")
    assign_playbook_to_selected.short_description = "Assign playbook based on category and phase"

    def mark_phase_completed(self, request, queryset):
        count = 0
        for md in queryset:
            phase = md.get_current_phase()
            if phase and phase < 4:
                setattr(md, f'phase{phase}_completed', timezone.now())
                setattr(md, f'phase{phase+1}_started', timezone.now())
                md.save()
                count += 1
        self.message_user(request, f"Updated {count} incidents")
    mark_phase_completed.short_description = "Mark current phase as completed"

    def export_for_report(self, request, queryset):
        import csv
        from django.http import HttpResponse
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="incidents_report.csv"'
        writer = csv.writer(response)
        writer.writerow(['ID', 'Subject', 'Accepted By', 'Phase', 'Role', 'Playbook', 'Phase1 Start', 'SLA Breached'])
        for md in queryset:
            writer.writerow([
                md.incident.id, md.incident.subject,
                md.accepted_by.username if md.accepted_by else '',
                md.get_current_phase(), md.get_assigned_role_display(),
                md.applied_playbook.name if md.applied_playbook else '',
                md.phase1_started, md.sla_breached
            ])
        return response
    export_for_report.short_description = "Export selected to CSV"