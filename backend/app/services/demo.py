"""Produces log records only. Never opens network connections or executes payloads."""
from datetime import timedelta
from app.models.entities import now, uid
from app.schemas.inputs import EventInput


def demo_events():
    base = now() - timedelta(hours=23)
    events = []
    def add(offset, host='gateway-prod', source='198.51.100.24', **fields):
        events.append(EventInput(event_id=uid(), timestamp=base + timedelta(seconds=offset), hostname=host, source_ip=source, destination_ip='10.20.0.' + str(10 + len(host)), **fields))
    for hour in range(24):
        offset = hour * 3500
        for i in range(12):
            add(offset+i*3, host=['gateway-prod','auth-server','db-primary'][hour%3], source=f'198.51.100.{24+hour%5}', event_type='ssh_failed', username='admin', destination_port=22, message='Simulated sshd: authentication failure')
        add(offset+45, event_type='login_success', username='admin', message='Simulated authentication accepted')
        if hour % 3 == 0:
            for port in range(20,44):
                add(offset+100+port, host='web-edge-01', source='203.0.113.82', event_type='connection', destination_port=port, protocol='TCP', message='Simulated network connection record')
        if hour % 4 == 0:
            add(offset+170, host='db-primary', event_type='file_modified', file_path='/etc/shadow', message='Simulated file integrity change')
            add(offset+180, host='workstation-07', source='203.0.113.19', event_type='process_start', process_name='powershell.exe', message='Simulated log: powershell -EncodedCommand [inert sample]')
        if hour % 5 == 0:
            add(offset+210, host='network-sensor', source='203.0.113.55', event_type='suricata_alert', severity='critical', message='SIMULATED suspicious outbound application protocol signature')
            for i in range(6):
                add(offset+230+i, host='auth-server', source='198.51.100.101', event_type='login_failed', username=f'user{i}', message='Simulated account authentication failure')
    return events
