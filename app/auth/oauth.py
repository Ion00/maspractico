from authlib.oauth2.rfc6749 import grants
from app.models import User, OAuth2Token
from datetime import datetime, timedelta

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        code.user_id = request.user.id
        db.session.add(code)
        db.session.commit()
    
    def query_authorization_code(self, code, client):
        return db.session.query(OAuth2Token).filter_by(code=code, client_id=client.client_id).first()
    
    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return db.session.query(User).get(authorization_code.user_id)
