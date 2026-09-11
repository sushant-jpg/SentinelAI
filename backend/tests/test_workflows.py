import json
from app.models.entities import now
from test_detection import event, ingest


def test_alert_incident_ai_workflow(client,accounts):
    created=ingest(client,accounts,[event('file_modified',file_path='/etc/shadow')]).json()
    key=created['alert_ids'][0]
    assert client.patch('/api/alerts/'+key,headers=accounts['viewer'],json={'status':'Resolved'}).status_code==403
    assert client.patch('/api/alerts/'+key,headers=accounts['analyst'],json={'status':'Investigating'}).status_code==200
    assert client.post(f'/api/alerts/{key}/notes',headers=accounts['analyst'],json={'text':'Review approved change window.'}).status_code==201
    detail=client.get('/api/alerts/'+key,headers=accounts['viewer']).json()
    assert len(detail['notes'])==1 and detail['events'][0]['file_path']=='/etc/shadow'
    incident=client.post('/api/incidents',headers=accounts['analyst'],json={'title':'Identity configuration review','related_alerts':[key,key]})
    assert incident.status_code==201
    iid=incident.json()['incident_id']
    assert client.patch('/api/incidents/'+iid,headers=accounts['analyst'],json={'status':'Resolved'}).status_code==422
    assert client.patch('/api/incidents/'+iid,headers=accounts['analyst'],json={'status':'Resolved','resolution':'Approved maintenance confirmed.'}).status_code==200
    detail=client.get('/api/incidents/'+iid,headers=accounts['viewer']).json()
    assert len(detail['related_alerts'])==1 and len(detail['timeline'])==2
    analysis=client.post('/api/ai/alerts/'+key,headers=accounts['viewer']).json()
    assert analysis['provider']=='local' and analysis['observed_evidence']['event_ids']==detail['related_alerts'][0]['evidence']['event_ids']
    metrics=client.get('/api/analytics',headers=accounts['viewer']).json()
    assert metrics['resolved_incidents']==1 and metrics['mttr_hours'] is not None


def test_validation_and_search(client,accounts):
    for record in [event(source_ip='not-an-ip'),event(destination_port=90000),event(timestamp='2020-01-01T00:00:00'),event(severity='panic')]:
        assert ingest(client,accounts,[record]).status_code==422
    assert client.get('/api/alerts?min_risk=90&max_risk=10',headers=accounts['viewer']).status_code==422
    assert client.get('/api/alerts?page=0',headers=accounts['viewer']).status_code==422
    assert client.get('/api/alerts/missing',headers=accounts['viewer']).status_code==404
    assert client.post('/api/incidents',headers=accounts['analyst'],json={'title':'Bad incident','related_alerts':['missing']}).status_code==404
    ingest(client,accounts,[event('file_modified',file_path='/etc/shadow')])
    for query,total in [('host=test-server',1),('severity=low',0),('q=%27%20OR%201%3D1--',0),('technique=T1098',1),('status=New',1)]:
        assert client.get('/api/alerts?'+query,headers=accounts['viewer']).json()['total']==total


def test_integrations(client,accounts):
    payload={'timestamp':now().isoformat(),'event_type':'alert','src_ip':'203.0.113.7','dest_ip':'10.0.0.4','alert':{'signature':'Test signature','severity':1}}
    response=client.post('/api/events/import/suricata',json=payload,headers=accounts['analyst'])
    assert response.status_code==201 and response.json()['alerts_created']==1
    assert client.post('/api/events/import/suricata',content=json.dumps(payload)+'\n'+json.dumps(payload),headers=accounts['analyst']).json()['duplicates']==2
    assert client.post('/api/events/import/wazuh',json={'timestamp':now().isoformat(),'rule':{'level':10,'description':'Test sensor alert'},'agent':{'name':'wazuh-test','ip':'10.0.0.6'}},headers=accounts['analyst']).status_code==201
    assert client.post('/api/events/import/wazuh',json={'invalid':True},headers=accounts['analyst']).status_code==422
    assert client.post('/api/events/import/suricata',content=b'\xff',headers=accounts['analyst']).status_code==422


def test_disable_rule_and_demo(client,accounts):
    assert client.patch('/api/rules/file_integrity',headers=accounts['admin'],json={'enabled':False}).status_code==200
    assert ingest(client,accounts,[event('file_modified',file_path='/etc/shadow')]).json()['alerts_created']==0
    response=client.post('/api/events/demo',headers=accounts['admin'])
    assert response.status_code==201 and response.json()['alerts_created']>20
    assert client.get('/api/assets',headers=accounts['viewer']).json()['items']
