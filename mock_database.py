"""
Mock Database Module for Testing
Replace Azure SQL operations with in-memory storage
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import secrets

class MockDatabase:
    """In-memory mock database for testing"""
    
    def __init__(self):
        self.users: Dict[str, dict] = {}
        self.users_by_email: Dict[str, str] = {}  # ADDED: email -> user_id mapping
        self.tokens: Dict[str, dict] = {}
        self.sessions: Dict[str, dict] = {}
        self.audit_logs: List[dict] = []
        self.api_key_to_user: Dict[str, str] = {}  # api_key_hash -> user_id
    
    def create_user(self, email: str, display_name: str, api_key_hash: str, api_key_encrypted: str = None) -> str:
        """Create a new user"""
        user_id = secrets.token_urlsafe(16)
        self.users[user_id] = {
            "user_id": user_id,
            "email": email,
            "display_name": display_name,
            "api_key_hash": api_key_hash,
            "api_key_encrypted": api_key_encrypted,
            "created_at": datetime.utcnow(),
            "last_login": datetime.utcnow(),
            "is_active": True
        }
        self.users_by_email[email] = user_id
        self.api_key_to_user[api_key_hash] = user_id  # ADDED: Map api_key_hash to user_id
        return user_id

    def get_encrypted_api_key(self, user_id: str) -> Optional[str]:
        """Get encrypted API key for a user"""
        user = self.users.get(user_id)
        return user.get("api_key_encrypted") if user else None
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get user by email"""
        for user in self.users.values():
            if user["email"] == email:
                return {
                    "user_id": user["user_id"],
                    "email": user["email"],
                    "display_name": user["display_name"],
                    "is_active": user["is_active"]
                }
        return None
    
    def get_user_by_api_key(self, api_key_hash: str) -> Optional[str]:
        """Get user_id by API key hash"""
        user_id = self.api_key_to_user.get(api_key_hash)
        if user_id and self.users.get(user_id, {}).get("is_active"):
            return user_id
        return None
    
    def store_tokens(self, user_id: str, access_token: str, refresh_token: str, 
                     token_expiry: datetime, scopes: str):
        """Store or update tokens for a user"""
        self.tokens[user_id] = {
            "user_id": user_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry,
            "scopes": scopes,
            "updated_at": datetime.utcnow()
        }
    
    def get_user_tokens(self, user_id: str) -> Optional[dict]:
        """Get tokens for a user"""
        token_data = self.tokens.get(user_id)
        if token_data:
            return {
                "access_token": token_data["access_token"],
                "refresh_token": token_data["refresh_token"],
                "token_expiry": token_data["token_expiry"],
                "scopes": token_data["scopes"].split()
            }
        return None
    
    def create_session(self, user_id: str, session_token: str, 
                       expires_at: datetime, ip_address: str, user_agent: str):
        """Create a new session"""
        self.sessions[session_token] = {
            "session_token": session_token,
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
    
    def get_user_from_session(self, session_token: str) -> Optional[str]:
        """Get user_id from session token if valid"""
        session = self.sessions.get(session_token)
        if session and session["expires_at"] > datetime.utcnow():
            return session["user_id"]
        return None
    
    def log_action(self, user_id: str, action: str, success: bool, 
                   source: str, details: str, ip_address: str):
        """Log an action"""
        # Truncate details if too long
        if len(details) > 1024:
            details = details[:1021] + "..."
        
        self.audit_logs.append({
            "user_id": user_id,
            "action": action,
            "timestamp": datetime.utcnow(),
            "success": success,
            "ip_address": ip_address,
            "source": source,
            "details": details
        })
    
    def update_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        if user_id in self.users:
            self.users[user_id]["last_login"] = datetime.utcnow()
    
    def clear_all(self):
        """Clear all data (useful for testing)"""
        self.users.clear()
        self.users_by_email.clear()
        self.tokens.clear()
        self.sessions.clear()
        self.audit_logs.clear()
        self.api_key_to_user.clear()


# Global mock database instance
_mock_db = MockDatabase()


def get_mock_db() -> MockDatabase:
    """Get the global mock database instance"""
    return _mock_db
