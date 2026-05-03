# fir_method_extension/management/commands/check_escalations.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from incidents.models import Incident
from fir_method_extension.models import MethodIncidentData
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Check for unhandled incidents older than 20 minutes and escalate them (SLA rule).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--minutes', type=int, default=20,
            help='Minutes threshold for escalation (default: 20)'
        )

    def handle(self, *args, **options):
        threshold_minutes = options['minutes']
        threshold = timezone.now() - timedelta(minutes=threshold_minutes)
        
        stalled_incidents = Incident.objects.filter(
            status__name__in=['Open', 'Blocked', 'New', 'Triage'], 
            date__lt=threshold
        ).annotate(
            comment_count=Count('comments')  
        ).filter(
            comment_count=0
        ).select_related('method_data').distinct()

        count = 0
        for inc in stalled_incidents:
            method_data, _ = MethodIncidentData.objects.get_or_create(incident=inc)
            
            if not method_data.escalated_to_l2:
             
                method_data.escalated_to_l2 = True
                method_data.l2_assigned_at = timezone.now()
                method_data.sla_breached = True
                method_data.assigned_role = 'l2_monitoring'
                method_data.role_assigned_at = timezone.now()
                method_data.save()
                
                logger.warning(
                    f" ESCALATION: Incident #{inc.id} '{inc.subject}' "
                    f"unhandled for >{threshold_minutes} min. Marked as escalated to L2."
                )
                count += 1

        self.stdout.write(self.style.SUCCESS(
            f'Checked escalations. Threshold: {threshold_minutes} min. Escalated: {count}'
        ))