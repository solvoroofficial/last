import os
import sys
import json

# Ensure project root is on sys.path so `from app import app` works when pytest
# collects this file as part of the `scripts` package.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app

def run_test():
    steps = []
    with app.test_client() as client:
        # Start the conversation
        r = client.post('/api/chatbot', json={'node': 'start'})
        print('STEP 1 - start')
        print(json.dumps(r.get_json(), indent=2))
        steps.append(r.get_json())

        # Choose 'I want to request a quote'
        r = client.post('/api/chatbot', json={'node': 'start', 'input': "I want to request a quote"})
        print('\nSTEP 2 - choose quote_request')
        print(json.dumps(r.get_json(), indent=2))
        steps.append(r.get_json())

        # Provide name (quote_request expects input 'name' then email)
        r = client.post('/api/chatbot', json={'node': 'quote_request', 'input': 'Test User'})
        print('\nSTEP 3 - provide name')
        print(json.dumps(r.get_json(), indent=2))
        steps.append(r.get_json())

        # Provide email
        r = client.post('/api/chatbot', json={'node': 'quote_email', 'input': 'test@example.com'})
        print('\nSTEP 4 - provide email')
        print(json.dumps(r.get_json(), indent=2))
        steps.append(r.get_json())

        # Provide mobile
        r = client.post('/api/chatbot', json={'node': 'quote_mobile', 'input': '9999999999'})
        print('\nSTEP 5 - provide mobile')
        print(json.dumps(r.get_json(), indent=2))
        steps.append(r.get_json())

        # Choose product 'T-Shirts'
        r = client.post('/api/chatbot', json={'node': 'quote_product', 'input': 'T-Shirts'})
        print('\nSTEP 6 - choose product')
        print(json.dumps(r.get_json(), indent=2))
        steps.append(r.get_json())

    return steps

if __name__ == '__main__':
    run_test()
