import pytest
from app import app, db, Customer, QuoteRequest

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client
    with app.app_context():
        db.drop_all()

def test_chatbot_start_node(client):
    res = client.post('/api/chatbot', json={'node': 'start'})
    assert res.status_code == 200
    data = res.get_json()
    assert data is not None
    assert 'Welcome to Prabha Graphics' in data.get('message', '')
    assert isinstance(data.get('options'), list)
    assert len(data.get('options')) >= 1

def test_chatbot_quote_option_transition(client):
    res = client.post('/api/chatbot', json={'node': 'start', 'input': 'I want to request a quote'})
    assert res.status_code == 200
    data = res.get_json()
    assert data.get('node') == 'quote_request'
    assert 'quote' in data.get('message', '').lower()

def test_admin_delete_customer_and_quote(client):
    with app.app_context():
        cust = Customer(name='ToDelete', email='del@ex.com', mobile='9999999999')
        qr = QuoteRequest(name='QuoteDel', email='q@ex.com', mobile='8888888888', product='T-Shirts')
        db.session.add_all([cust, qr])
        db.session.commit()
        cid = cust.id
        qid = qr.id
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
    res1 = client.post(f'/admin/customer/{cid}/delete', follow_redirects=True)
    assert res1.status_code == 200
    with app.app_context():
        assert db.session.get(Customer, cid) is None
    res2 = client.post(f'/admin/quote/{qid}/delete', follow_redirects=True)
    assert res2.status_code == 200
    with app.app_context():
        assert db.session.get(QuoteRequest, qid) is None
