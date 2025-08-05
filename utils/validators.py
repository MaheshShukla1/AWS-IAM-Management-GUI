import re,json, logging
def validate_username(self, username):
        if len(username) < 1 or len(username) > 64:
            return False
        if not re.match(r'^[a-zA-Z0-9+=,.@-]+$', username):
            return False
        return True

def validate_password(self, password):
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[@$!%*?&]', password):
            return False
        return True

def validate_json(self, json_str):
    try:
        json.loads(json_str)
        return True
    except ValueError:
        return False
    
