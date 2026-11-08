from fastapi.testclient import TestClient
from intentx.api.app import create_app
from intentx.application.service import ApplicationResult
from intentx.ui.clarification import clarification_help


def test_relevant_examples_and_missing_targets():
    help = clarification_help('please fix the internet', missing_entities=('PORT',))
    assert help['missing_entities'] == ['PORT']
    assert {s['topic'] for s in help['suggestions']} == {'network'}
    assert all(not s['state_changing'] for s in help['suggestions'])


def test_unknown_input_and_untrusted_targets_are_not_completed():
    for text in ('asdf zxcv', '<script>alert(1)</script>', 'delete /etc/passwd; $(id)'):
        help = clarification_help(text)
        assert 1 <= len(help['suggestions']) <= 6
        assert all('passwd' not in s['text'] and '<script>' not in s['text'] and '$(id)' not in s['text'] for s in help['suggestions'])
    assert 'could not identify' in clarification_help('asdf zxcv')['message']


def test_ambiguous_request_keeps_multiple_topics_and_labels_changes():
    assert {s['topic'] for s in clarification_help('check processes and network')['suggestions']} == {'processes','network'}
    help = clarification_help('create a file')
    assert all(s['state_changing'] for s in help['suggestions'])
    assert all('/app/logs/demo-' in s['text'] for s in help['suggestions'])


def test_api_help_is_descriptive_and_never_retries_or_executes():
    class FakeService:
        calls = []
        def handle(self, request):
            self.calls.append(request)
            return ApplicationResult(status='CLARIFICATION_REQUIRED', stage='ANALYSIS', reason='Missing target', executed=False, missing_entities=('PATH',))
    service=FakeService();client=TestClient(create_app(application_service=service))
    response=client.post('/api/v1/intent', json=dict(text='read this file',role='VIEWER',environment='DEV',correlation_id='test',execute=False))
    body=response.json()
    assert response.status_code == 200
    assert body['status'] == 'CLARIFICATION_REQUIRED' and body['plan'] is None and body['executed'] is False
    assert body['clarification']['missing_entities'] == ['PATH']
    assert len(service.calls)==1 and service.calls[0].execute is False


def test_no_suggestions_added_to_denials_or_success():
    class FakeService:
        def __init__(self,status):self.status=status
        def handle(self,request):return ApplicationResult(status=self.status, stage='TEST', reason='test',executed=False)
    for status in ('DENY','PLAN_CREATED','EXECUTION_BLOCKED'):
        c=TestClient(create_app(application_service=FakeService(status)))
        body=c.post('/api/v1/intent',json=dict(text='request',role='VIEWER',environment='DEV',correlation_id='t')).json()
        assert 'clarification' not in body
