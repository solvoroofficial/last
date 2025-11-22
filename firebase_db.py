import os
import json
from typing import Optional, List, Dict

firebase_app = None
db_client = None


def init_firebase():
    """Initialize Firebase Admin SDK using a service account JSON file or
    a JSON string in the environment variable `FIREBASE_SERVICE_ACCOUNT_JSON`.
    Uses Firestore as the database.
    """
    global firebase_app, db_client
    if firebase_app is not None:
        return True

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except Exception:
        # firebase-admin not installed
        return False

    cred = None
    sa_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
    sa_json = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON')

    if sa_path and os.path.exists(sa_path):
        cred = credentials.Certificate(sa_path)
    elif sa_json:
        try:
            data = json.loads(sa_json)
            cred = credentials.Certificate(data)
        except Exception:
            return False
    else:
        return False

    # Allow specifying a storage bucket via env var
    storage_bucket = os.environ.get('FIREBASE_STORAGE_BUCKET')
    init_kwargs = {'credential': cred}
    if storage_bucket:
        # initialize_app takes options dict as second arg in some contexts
        try:
            firebase_app = firebase_admin.initialize_app(cred, {'storageBucket': storage_bucket})
        except Exception:
            # fallback to default init
            firebase_app = firebase_admin.initialize_app(cred)
    else:
        firebase_app = firebase_admin.initialize_app(cred)

    db_client = firestore.client()
    return True


def _ensure():
    if db_client is None:
        if not init_firebase():
            raise RuntimeError('Firebase not initialized or credentials missing')


# ----- Storage helpers -----
def upload_fileobj_to_storage(file_obj, destination_path: str, content_type: str = None) -> str:
    """Upload a file-like object to the configured Firebase Storage bucket.
    Returns the public URL of the uploaded object.
    """
    _ensure()
    from firebase_admin import storage as _storage
    bucket = _storage.bucket()
    blob = bucket.blob(destination_path)
    # file_obj should be a file-like object
    if content_type:
        blob.upload_from_file(file_obj, content_type=content_type)
    else:
        blob.upload_from_file(file_obj)
    try:
        blob.make_public()
        return blob.public_url
    except Exception:
        # If cannot make public, return storage path
        return f'gs://{bucket.name}/{destination_path}'


def delete_blob(storage_path: str):
    """Delete a blob from the default storage bucket. `storage_path` should be the blob name or full gs:// URL."""
    _ensure()
    from firebase_admin import storage as _storage
    bucket = _storage.bucket()
    key = storage_path
    if storage_path.startswith('gs://'):
        # gs://bucket/name
        parts = storage_path[5:].split('/', 1)
        if len(parts) == 2:
            key = parts[1]
    blob = bucket.blob(key)
    try:
        blob.delete()
    except Exception:
        pass


# ----- User functions -----
def create_user(user_id: str, data: Dict):
    _ensure()
    db_client.collection('users').document(user_id).set(data)


def get_user_by_id(user_id: str) -> Optional[Dict]:
    _ensure()
    doc = db_client.collection('users').document(user_id).get()
    return doc.to_dict() if doc.exists else None


def get_user_by_email(email: str) -> Optional[Dict]:
    _ensure()
    docs = db_client.collection('users').where('email', '==', email).limit(1).stream()
    for d in docs:
        dct = d.to_dict()
        dct['id'] = d.id
        return dct
    return None


# ----- Customers -----
def add_customer(data: Dict) -> str:
    _ensure()
    doc_ref = db_client.collection('customers').document()
    doc_ref.set(data)
    return doc_ref.id


def list_customers() -> List[Dict]:
    _ensure()
    docs = db_client.collection('customers').order_by('created_at', direction='DESCENDING').stream()
    result = []
    for d in docs:
        item = d.to_dict()
        item['id'] = d.id
        result.append(item)
    return result


def get_customer(customer_id: str) -> Optional[Dict]:
    _ensure()
    doc = db_client.collection('customers').document(customer_id).get()
    return doc.to_dict() if doc.exists else None


def update_customer(customer_id: str, updates: Dict):
    _ensure()
    db_client.collection('customers').document(customer_id).update(updates)


def delete_customer(customer_id: str):
    _ensure()
    db_client.collection('customers').document(customer_id).delete()


# ----- Quotes -----
def add_quote(data: Dict) -> str:
    _ensure()
    doc_ref = db_client.collection('quotes').document()
    doc_ref.set(data)
    return doc_ref.id


def list_quotes() -> List[Dict]:
    _ensure()
    docs = db_client.collection('quotes').order_by('created_at', direction='DESCENDING').stream()
    result = []
    for d in docs:
        item = d.to_dict()
        item['id'] = d.id
        result.append(item)
    return result


def get_quote(quote_id: str) -> Optional[Dict]:
    _ensure()
    doc = db_client.collection('quotes').document(quote_id).get()
    return doc.to_dict() if doc.exists else None


def update_quote(quote_id: str, updates: Dict):
    _ensure()
    db_client.collection('quotes').document(quote_id).update(updates)


def delete_quote(quote_id: str):
    _ensure()
    db_client.collection('quotes').document(quote_id).delete()


# ----- Products -----
def add_product(data: Dict) -> str:
    _ensure()
    doc_ref = db_client.collection('products').document()
    doc_ref.set(data)
    return doc_ref.id


def list_products() -> List[Dict]:
    _ensure()
    docs = db_client.collection('products').order_by('created_at', direction='DESCENDING').stream()
    result = []
    for d in docs:
        item = d.to_dict()
        item['id'] = d.id
        result.append(item)
    return result


def get_product(product_id: str) -> Optional[Dict]:
    _ensure()
    doc = db_client.collection('products').document(product_id).get()
    return doc.to_dict() if doc.exists else None


def update_product(product_id: str, updates: Dict):
    _ensure()
    db_client.collection('products').document(product_id).update(updates)


def delete_product(product_id: str):
    _ensure()
    db_client.collection('products').document(product_id).delete()


def ensure_initialized() -> bool:
    try:
        return init_firebase()
    except Exception:
        return False
