from django.db import models
from django.contrib.auth.models import User
from incidents.models import Incident, IncidentCategory


class Playbook(models.Model):
    name = models.CharField(max_length=200, verbose_name='Playbook Name')
    description = models.TextField(blank=True, verbose_name='Description')
    category = models.ForeignKey(
        IncidentCategory, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='playbooks', verbose_name='Incident Category'
    )
    phase = models.PositiveSmallIntegerField(
        choices=[
            (1, 'Phase 1: Detection & Analysis'),
            (2, 'Phase 2: Damage Containment'),
            (3, 'Phase 3: Eradication & Recovery'),
            (4, 'Phase 4: Post-Incident Analysis'),
        ],
        verbose_name='Applicable Phase'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True, verbose_name='Active')
    version = models.CharField(max_length=20, default='1.0', verbose_name='Version')

    class Meta:
        verbose_name = 'Playbook'
        verbose_name_plural = 'Playbooks'
        ordering = ['category', 'phase', 'name']

    def __str__(self):
        return f"{self.name} (Phase {self.phase})"


class PlaybookStep(models.Model):
    playbook = models.ForeignKey(
        Playbook, on_delete=models.CASCADE, related_name='steps', verbose_name='Playbook'
    )
    order = models.PositiveSmallIntegerField(verbose_name='Step Order')
    title = models.CharField(max_length=200, verbose_name='Step Title')
    instruction = models.TextField(verbose_name='Instruction')
    expected_outcome = models.TextField(blank=True, verbose_name='Expected Outcome')
    reference_url = models.URLField(blank=True, verbose_name='Reference URL')

    class Meta:
        verbose_name = 'Playbook Step'
        verbose_name_plural = 'Playbook Steps'
        ordering = ['order']
        unique_together = ['playbook', 'order']

    def __str__(self):
        return f"Step {self.order}: {self.title}"


class PlaybookStepExecution(models.Model):
    """Tracks completion status of playbook steps for a specific incident"""
    incident_data = models.ForeignKey(
        'MethodIncidentData', on_delete=models.CASCADE,
        related_name='step_executions', verbose_name='Incident Data'
    )
    step = models.ForeignKey(PlaybookStep, on_delete=models.PROTECT, verbose_name='Step')
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('completed', 'Completed'),
            ('skipped', 'Skipped'),
            ('failed', 'Failed'),
        ],
        default='pending',
        verbose_name='Status'
    )
    executed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, verbose_name='Executed By'
    )
    executed_at = models.DateTimeField(null=True, blank=True, verbose_name='Executed At')
    notes = models.TextField(blank=True, verbose_name='Execution Notes')

    class Meta:
        verbose_name = 'Step Execution'
        verbose_name_plural = 'Step Executions'
        unique_together = ['incident_data', 'step']
        ordering = ['step__order']

    def __str__(self):
        return f"{self.step.title} ({self.status}) for Incident #{self.incident_data.incident.id}"


class MethodIncidentData(models.Model):
    incident = models.OneToOneField(
        Incident, on_delete=models.CASCADE,
        related_name='method_data', verbose_name='Incident'
    )


    phase1_started = models.DateTimeField(null=True, blank=True, verbose_name='Phase 1 Start')
    phase1_completed = models.DateTimeField(null=True, blank=True, verbose_name='Phase 1 End')
    is_false_positive = models.BooleanField(default=False, verbose_name='Is False Positive')
    false_positive_reason = models.TextField(blank=True, verbose_name='Reason if False Positive')
    escalated_to_l2 = models.BooleanField(default=False, verbose_name='Escalated to L2')
    l2_assigned_at = models.DateTimeField(null=True, blank=True, verbose_name='L2 Assignment Time')

    phase2_started = models.DateTimeField(null=True, blank=True, verbose_name='Phase 2 Start')
    phase2_completed = models.DateTimeField(null=True, blank=True, verbose_name='Phase 2 End')
    playbook_used = models.CharField(max_length=150, blank=True, verbose_name='Applied Playbook')
    custom_containment_actions = models.TextField(blank=True, verbose_name='Custom Containment Actions')
    localized_at = models.DateTimeField(null=True, blank=True, verbose_name='Containment Completed')

    phase3_started = models.DateTimeField(null=True, blank=True, verbose_name='Phase 3 Start')
    phase3_completed = models.DateTimeField(null=True, blank=True, verbose_name='Phase 3 End')
    recovery_plan = models.TextField(blank=True, verbose_name='Recovery Plan')
    recovery_verified = models.BooleanField(default=False, verbose_name='Recovery Verified')
    recovered_at = models.DateTimeField(null=True, blank=True, verbose_name='Recovery Completed')

    phase4_started = models.DateTimeField(null=True, blank=True, verbose_name='Phase 4 Start')
    phase4_completed = models.DateTimeField(null=True, blank=True, verbose_name='Phase 4 End')
    lessons_learned = models.TextField(blank=True, verbose_name='Lessons Learned')
    recommendations = models.TextField(blank=True, verbose_name='Recommendations')
    improvements_implemented = models.BooleanField(default=False, verbose_name='Improvements Implemented')
    closed_at = models.DateTimeField(null=True, blank=True, verbose_name='Official Closure Time')

    ROLE_CHOICES = [
        ('l1_monitoring', 'L1 Monitoring'),
        ('l2_monitoring', 'L2 Monitoring'),
        ('security_dept', 'Security Department'),
        ('it_dept', 'IT Department'),
        ('security_analyst', 'Security Analyst'),
        ('ir_manager', 'IR Manager'),
        ('management', 'Management/Client'),
        ('external_expert', 'External Expert'),
    ]

    analyst_notes = models.TextField(
        blank=True,
        verbose_name='Analyst Notes',
        help_text='Additional observations, findings, or context added during incident handling'
    )
    notes_updated_at = models.DateTimeField(null=True, blank=True, verbose_name='Notes Last Updated')


    assigned_role = models.CharField(
        max_length=30, choices=ROLE_CHOICES, null=True, blank=True, verbose_name='Assigned Role'
    )
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assigned_method_incidents', verbose_name='Assigned To'
    )
    role_assigned_at = models.DateTimeField(null=True, blank=True, verbose_name='Role Assigned At')


    accepted_at = models.DateTimeField(null=True, blank=True, verbose_name='Accepted At')
    accepted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='accepted_method_incidents', verbose_name='Accepted By'
    )


    ir_manager = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='managed_method_incidents', verbose_name='IR Manager'
    )
    sla_deadline = models.DateTimeField(null=True, blank=True, verbose_name='SLA Deadline')
    sla_breached = models.BooleanField(default=False, verbose_name='SLA Breached')

    applied_playbook = models.ForeignKey(
        Playbook, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='applied_incidents', verbose_name='Applied Playbook'
    )
    playbook_started_at = models.DateTimeField(null=True, blank=True, verbose_name='Playbook Started At')
    playbook_completed_at = models.DateTimeField(null=True, blank=True, verbose_name='Playbook Completed At')
    playbook_notes = models.TextField(blank=True, verbose_name='Playbook Execution Notes')

    class Meta:
        verbose_name = 'Incident Method Data'
        verbose_name_plural = 'Incident Method Data'
        ordering = ['-incident__date']

    def __str__(self):
        return f"MethodData for Incident #{self.incident.id}"

    def get_current_phase(self):

        status_name = getattr(self.incident.status, 'name', '').lower().strip()
        phase_map = {
            'new': 1, 'open': 1, 'triage': 1, 'analyzing': 1, 'assigned': 1, 'blocked': 1,
            'contained': 2, 'mitigated': 2, 'isolated': 2, 'containing': 2, 'localizing': 2,
            'recovering': 3, 'restoring': 3, 'eradicated': 3, 'cleaning': 3, 'verifying': 3,
            'resolved': 4, 'closed': 4, 'completed': 4, 'review': 4, 'postmortem': 4,
        }
        active_phase = phase_map.get(status_name)
        if active_phase:
            return active_phase
        
        if self.phase4_started: 
            return 4
        if self.phase3_started: 
            return 3
        if self.phase2_started: 
            return 2
        if self.phase1_started: 
            return 1
        return 1
    
    def get_phase_transition_log(self):

        transitions = []
        phase_fields = [
            ('phase1_started', 'Phase 1 Started'),
            ('phase1_completed', 'Phase 1 Completed'),
            ('phase2_started', 'Phase 2 Started'),
            ('phase2_completed', 'Phase 2 Completed'),
            ('phase3_started', 'Phase 3 Started'),
            ('phase3_completed', 'Phase 3 Completed'),
            ('phase4_completed', 'Phase 4 Completed'),
            ('closed_at', 'Incident Closed'),
        ]
        for field_name, label in phase_fields:
            timestamp = getattr(self, field_name)
            if timestamp:
                transitions.append({
                    'label': label,
                    'timestamp': timestamp,
                    'phase': field_name.split('_')[0].replace('phase', '')
                })
        return sorted(transitions, key=lambda x: x['timestamp'])
    
    def get_phase_display_data(self):

        phases = [
            {'key': 'detection', 'name': 'Обнаружение и анализ', 'order': 1},
            {'key': 'minimization', 'name': 'Минимизация ущерба', 'order': 2},
            {'key': 'eradication', 'name': 'Ликвидация последствий', 'order': 3},
            {'key': 'post_mortem', 'name': 'Постинцидентный анализ', 'order': 4},
        ]
        current_order = next((p['order'] for p in phases if p['key'] == self.current_phase), 1)
        
        result = []
        for phase in phases:
            if phase['order'] < current_order:
                status = 'completed'
            elif phase['order'] == current_order:
                status = 'active'
            else:
                status = 'pending'
            result.append({**phase, 'status': status})
        return result