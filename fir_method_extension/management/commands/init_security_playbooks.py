
from django.core.management.base import BaseCommand
from fir_method_extension.models import Playbook, PlaybookStep
from incidents.models import IncidentCategory

class Command(BaseCommand):
    help = 'Initialize security playbooks for common incident types'

    def handle(self, *args, **options):
     
        categories = {
            1: 'Phishing',
            3: 'Scam (web)',
            4: 'Malware',
            5: 'Dataleak',
            12: 'Compromise',
            14: 'Vulnerability',
            18: 'ThreatIntel',
            21: 'DoS',
        }
        
        playbooks = self._get_playbook_definitions(categories)
        
        for pb_def in playbooks:
            
            category = None
            if pb_def.get('category_id'):
                try:
                    category = IncidentCategory.objects.get(id=pb_def['category_id'])
                except IncidentCategory.DoesNotExist:
                    self.stdout.write(self.style.WARNING(
                        f'Category ID {pb_def["category_id"]} not found, using None'
                    ))
            
            playbook, created = Playbook.objects.get_or_create(
                name=pb_def['name'],
                defaults={
                    'description': pb_def['description'],
                    'category': category,
                    'phase': pb_def['phase'], 
                    'is_active': True,
                    'version': '1.0'
                }
            )
            
            if created:
                self.stdout.write(f'Created playbook: {playbook.name}')
                self._create_steps(playbook, pb_def['steps'])
            else:
                self.stdout.write(f'Playbook exists: {playbook.name}')
                
                
        self.stdout.write(self.style.SUCCESS('Playbook initialization complete'))

    def _get_playbook_definitions(self, categories):
        return [
            self._brute_force_success_playbook(categories),
            self._port_forwarding_playbook(categories),
            self._remote_admin_tool_playbook(categories),
            self._bad_reputation_ioc_playbook(categories),
            self._system_recon_playbook(categories)
        ]

    def _brute_force_success_playbook(self, categories):
        return {
            'name': 'Brute Force with Successful Login',
            'description': 'Response playbook for multiple failed authentication attempts followed by successful login under non-privileged account',
            'category_id': 12, 
            'phase': 1,  
            'steps': [
                {
                    'order': 1,
                    'title': 'Verify authentication logs',
                    'instruction': 'Review auth.log/Security.evtx for failed attempts pattern: source IP, usernames, timestamps. Use grep or SIEM query.',
                    'expected_outcome': 'List of failed attempts with timestamps and source IP',
                    'reference_url': ''
                },
                {
                    'order': 2,
                    'title': 'Check account status',
                    'instruction': 'Verify if the account is legitimate, disabled, or potentially compromised. Check last password change and group memberships.',
                    'expected_outcome': 'Account status: active/suspended/locked, last login time',
                    'reference_url': ''
                },
                {
                    'order': 3,
                    'title': 'Isolate source IP',
                    'instruction': 'If source IP is external or suspicious, add to firewall blocklist. Document justification in incident notes.',
                    'expected_outcome': 'IP blocked at perimeter firewall or documented as false positive',
                    'reference_url': ''
                },
                {
                    'order': 4,
                    'title': 'Force password reset',
                    'instruction': 'Initiate password reset for the affected account. Notify user via secure channel (not email if compromised).',
                    'expected_outcome': 'Password reset confirmation, user notified',
                    'reference_url': ''
                },
                {
                    'order': 5,
                    'title': 'Review session activity',
                    'instruction': 'Analyze commands executed, files accessed, and network connections during the suspicious session.',
                    'expected_outcome': 'Session activity report with IOCs if any',
                    'reference_url': ''
                },
                {
                    'order': 6,
                    'title': 'Update detection rules',
                    'instruction': 'If new TTPs observed, update SIEM correlation rules and playbook for future incidents.',
                    'expected_outcome': 'Rule update ticket created or documentation updated',
                    'reference_url': ''
                }
            ]
        }

    def _port_forwarding_playbook(self, categories):
        return {
            'name': 'Port Forwarding / Tunneling Detection',
            'description': 'Response playbook for detected network port forwarding or tunneling attempts',
            'category_id': 21,
            'phase': 2,  
            'steps': [
                {
                    'order': 1,
                    'title': 'Identify tunneling method',
                    'instruction': 'Determine if SSH, ICMP, DNS, or HTTP tunneling. Check process name, parent process, and command line arguments.',
                    'expected_outcome': 'Tunneling method identified with process details',
                    'reference_url': ''
                },
                {
                    'order': 2,
                    'title': 'Block outbound connection',
                    'instruction': 'Terminate the suspicious connection at firewall/EDR level. Preserve logs for forensics before blocking.',
                    'expected_outcome': 'Connection terminated, logs preserved',
                    'reference_url': ''
                },
                {
                    'order': 3,
                    'title': 'Isolate affected host',
                    'instruction': 'If host shows signs of compromise, isolate from network (VLAN change or host firewall rules).',
                    'expected_outcome': 'Host isolated, network access restricted',
                    'reference_url': ''
                },
                {
                    'order': 4,
                    'title': 'Collect forensic artifacts',
                    'instruction': 'Capture memory dump, process list, network connections, and relevant logs before remediation.',
                    'expected_outcome': 'Forensic package created and stored securely',
                    'reference_url': ''
                },
                {
                    'order': 5,
                    'title': 'Scan for persistence',
                    'instruction': 'Check scheduled tasks, startup items, services, and registry for persistence mechanisms.',
                    'expected_outcome': 'Persistence artifacts documented or removed',
                    'reference_url': ''
                },
                {
                    'order': 6,
                    'title': 'Restore and monitor',
                    'instruction': 'After cleanup, restore host to production with enhanced monitoring for 72 hours.',
                    'expected_outcome': 'Host restored, monitoring rules applied',
                    'reference_url': ''
                }
            ]
        }

    def _remote_admin_tool_playbook(self, categories):
        return {
            'name': 'Remote Administration Tool Detection',
            'description': 'Response playbook for detection of known remote admin utilities (RATs, RMM tools) execution',
            'category_id': 4,
            'phase': 2, 
            'steps': [
                {
                    'order': 1,
                    'title': 'Verify tool legitimacy',
                    'instruction': 'Check if the tool is approved for use in the organization. Verify digital signature and installation path.',
                    'expected_outcome': 'Tool status: approved/unapproved, signature valid/invalid',
                    'reference_url': ''
                },
                {
                    'order': 2,
                    'title': 'Terminate malicious process',
                    'instruction': 'If unapproved, terminate the process and any child processes via EDR or taskkill. Log the action.',
                    'expected_outcome': 'Process terminated, PID logged',
                    'reference_url': ''
                },
                {
                    'order': 3,
                    'title': 'Block network indicators',
                    'instruction': 'Add C2 domains/IPs to blocklist. Check firewall logs for historical connections to these indicators.',
                    'expected_outcome': 'IOCs blocked, historical connections documented',
                    'reference_url': ''
                },
                {
                    'order': 4,
                    'title': 'Scan for lateral movement',
                    'instruction': 'Check for suspicious RDP, SMB, or WMI activity from the affected host to other systems.',
                    'expected_outcome': 'Lateral movement indicators documented',
                    'reference_url': ''
                },
                {
                    'order': 5,
                    'title': 'Full system scan',
                    'instruction': 'Run offline AV/EDR scan and check for additional payloads or droppers in temp directories.',
                    'expected_outcome': 'Scan results with detected items',
                    'reference_url': ''
                },
                {
                    'order': 6,
                    'title': 'Update application control',
                    'instruction': 'Add hash/path rules to application control policy to prevent future execution of this tool.',
                    'expected_outcome': 'Application control rule deployed',
                    'reference_url': ''
                }
            ]
        }

    def _bad_reputation_ioc_playbook(self, categories):
        return {
            'name': 'Bad Reputation IOC Connection',
            'description': 'Response playbook for connections to IP/URL with negative reputation (blacklists, threat feeds)',
            'category_id': 18, 
            'phase': 1, 
            'steps': [
                {
                    'order': 1,
                    'title': 'Validate IOC reputation',
                    'instruction': 'Query multiple threat intel sources (MISP, VT, AbuseIPDB) to confirm reputation score and context.',
                    'expected_outcome': 'Reputation report with sources and confidence level',
                    'reference_url': ''
                },
                {
                    'order': 2,
                    'title': 'Identify affected asset',
                    'instruction': 'Determine which internal host initiated the connection. Check process and user context.',
                    'expected_outcome': 'Asset ID, process name, user account identified',
                    'reference_url': ''
                },
                {
                    'order': 3,
                    'title': 'Block at perimeter',
                    'instruction': 'Add IOC to firewall, proxy, and DNS sinkhole. Verify block is effective with test connection.',
                    'expected_outcome': 'IOC blocked across security controls',
                    'reference_url': ''
                },
                {
                    'order': 4,
                    'title': 'Assess data exposure',
                    'instruction': 'Review traffic volume and payload to determine if sensitive data was exfiltrated.',
                    'expected_outcome': 'Data exposure assessment: none/low/medium/high',
                    'reference_url': ''
                },
                {
                    'order': 5,
                    'title': 'Scan for malware',
                    'instruction': 'Run targeted scan on affected host for malware that may have initiated the connection.',
                    'expected_outcome': 'Scan results with detected threats',
                    'reference_url': ''
                },
                {
                    'order': 6,
                    'title': 'Update threat intelligence',
                    'instruction': 'If new IOC, submit to internal MISP and relevant ISACs. Document attribution if possible.',
                    'expected_outcome': 'IOC submitted to intel platforms, attribution notes',
                    'reference_url': ''
                }
            ]
        }

    def _system_recon_playbook(self, categories):
        return {
            'name': 'System Reconnaissance via CLI',
            'description': 'Response playbook for detected system information gathering via command line utilities',
            'category_id': 14, 
            'phase': 1,  
            'steps': [
                {
                    'order': 1,
                    'title': 'Identify reconnaissance commands',
                    'instruction': 'Parse command history/logs for recon tools: whoami, ipconfig, net user, systeminfo, etc.',
                    'expected_outcome': 'List of executed recon commands with timestamps',
                    'reference_url': ''
                },
                {
                    'order': 2,
                    'title': 'Check user context',
                    'instruction': 'Determine if commands were run by legitimate user, service account, or unknown identity.',
                    'expected_outcome': 'User identity verified: legitimate/suspicious/unknown',
                    'reference_url': ''
                },
                {
                    'order': 3,
                    'title': 'Review subsequent activity',
                    'instruction': 'Check for commands following recon that indicate exploitation or lateral movement.',
                    'expected_outcome': 'Post-recon activity timeline',
                    'reference_url': ''
                },
                {
                    'order': 4,
                    'title': 'Reset credentials if needed',
                    'instruction': 'If recon targeted credential harvesting, force password reset for affected accounts.',
                    'expected_outcome': 'Credentials reset, users notified',
                    'reference_url': ''
                },
                {
                    'order': 5,
                    'title': 'Enhance command logging',
                    'instruction': 'Enable detailed command auditing (PowerShell transcription, bash history with timestamps).',
                    'expected_outcome': 'Enhanced logging configured and verified',
                    'expected_outcome': 'Enhanced logging configured and verified',
                    'reference_url': ''
                },
                {
                    'order': 6,
                    'title': 'Update detection rules',
                    'instruction': 'Create or tune SIEM rules to detect similar recon patterns with lower false positive rate.',
                    'expected_outcome': 'Detection rule deployed with test results',
                    'reference_url': ''
                }
            ]
        }

    def _create_steps(self, playbook, steps_def):
        for step_def in steps_def:
            PlaybookStep.objects.get_or_create(
                playbook=playbook,
                order=step_def['order'],
                defaults={
                    'title': step_def['title'],
                    'instruction': step_def['instruction'],
                    'expected_outcome': step_def.get('expected_outcome', ''),
                    'reference_url': step_def.get('reference_url', '')
                }
            )
            self.stdout.write(f'  - Added step {step_def["order"]}: {step_def["title"]}')
