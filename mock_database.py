"""
Mock Database Module for Testing
Replace Azure SQL operations with in-memory storage
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import secrets

class MockDatabase:
    def __init__(self):
        self.users = {}  # email -> user_data
        self.tokens = {}  # user_id -> token_data
        self.sessions = {}  # session_token -> session_data
        self.audit_logs = []  # list of log entries
        
    def create_user(self, email: str, display_name: str) -> str:
        """Create user - NO API KEY"""
        user_id = secrets.token_urlsafe(16)
        email = email.lower().strip()
        
        self.users[email] = {
            "user_id": user_id,
            "email": email,
            "display_name": display_name,
            "created_at": datetime.utcnow(),
            "last_login": datetime.utcnow(),
            "is_active": True
        }
        
        return user_id
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get user by email"""
        email = email.lower().strip()
        return self.users.get(email)
    
    def store_tokens(self, user_id: str, access_token: str, refresh_token: str, token_expiry: datetime, scopes: str):
        """Store tokens for user"""
        self.tokens[user_id] = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry,
            "scopes": scopes,
            "updated_at": datetime.utcnow()
        }
    
    def get_user_tokens(self, user_id: str) -> Optional[dict]:
        """Get tokens for user"""
        return self.tokens.get(user_id)
    
    def update_last_login(self, user_id: str):
        """Update last login timestamp"""
        # Find user by user_id
        for email, user_data in self.users.items():
            if user_data["user_id"] == user_id:
                user_data["last_login"] = datetime.utcnow()
                break
    
    def create_session(self, user_id: str, session_token: str, expires_at: datetime, ip_address: str, user_agent: str):
        """Create session"""
        self.sessions[session_token] = {
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
    
    def get_user_from_session(self, session_token: str) -> Optional[str]:
        """Get user_id from valid session"""
        session = self.sessions.get(session_token)
        if session and session["expires_at"] > datetime.utcnow():
            return session["user_id"]
        return None
    
    def log_action(self, user_id: str, action: str, success: bool, source: str, details: str, ip_address: str):
        """Log an action"""
        self.audit_logs.append({
            "user_id": user_id,
            "action": action,
            "timestamp": datetime.utcnow(),
            "success": success,
            "ip_address": ip_address,
            "source": source,
            "details": details[:1024] if details else ""
        })


# Global mock database instance
_mock_db = None

def get_mock_db() -> MockDatabase:
    """Get or create the global mock database instance"""
    global _mock_db
    if _mock_db is None:
        _mock_db = MockDatabase()
    return _mock_db
