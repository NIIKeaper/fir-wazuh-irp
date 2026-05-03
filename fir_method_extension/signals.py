from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.utils import timezone
from incidents.models import Incident
from fir_method_extension.models import MethodIncidentData


STATUS_PHASE_MAP = {
    'new': 1, 'open': 1, 'triage': 1, 'analyzing': 1, 'assigned': 1, 'blocked': 1,
    'contained': 2, 'mitigated': 2, 'isolated': 2, 'containing': 2, 'localizing': 2,
    'recovering': 3, 'restoring': 3, 'eradicated': 3, 'cleaning': 3, 'verifying': 3,
    'resolved': 4, 'closed': 4, 'completed': 4, 'review': 4, 'postmortem': 4,
}

@receiver(post_save, sender=Incident)
def create_method_data_for_incident(sender, instance, created, **kwargs):
    
    if created:
        MethodIncidentData.objects.get_or_create(incident=instance)

@receiver(pre_save, sender=Incident)
def update_method_phases_on_status_change(sender, instance, **kwargs):

    if not instance.pk:
        return  

    try:
        old_instance = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return


    if old_instance.status_id == instance.status_id:
        return

    method_data, _ = MethodIncidentData.objects.get_or_create(incident=instance)
    
    new_status_name = getattr(instance.status, 'name', '').lower().strip()
    new_phase = STATUS_PHASE_MAP.get(new_status_name, 1)
    now = timezone.now()

    if new_phase == 1 and not method_data.phase1_started:
        method_data.phase1_started = now
        
    elif new_phase == 2 and not method_data.phase2_started:
        method_data.phase1_completed = method_data.phase1_completed or now
        method_data.phase2_started = now
        
    elif new_phase == 3 and not method_data.phase3_started:
        method_data.phase2_completed = method_data.phase2_completed or now
        method_data.phase3_started = now
        
    elif new_phase == 4 and not method_data.phase4_started:
        method_data.phase3_completed = method_data.phase3_completed or now
        method_data.phase4_started = now

    if new_phase == 4 and new_status_name in ['closed', 'completed']:
        method_data.phase4_completed = method_data.phase4_completed or now
        method_data.closed_at = now

    method_data.save(update_fields=[
        'phase1_started', 'phase1_completed',
        'phase2_started', 'phase2_completed',
        'phase3_started', 'phase3_completed',
        'phase4_started', 'phase4_completed',
        'closed_at'
    ])