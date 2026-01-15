from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from dotenv import load_dotenv
import os
import requests
import io
import traceback
import asyncio
from typing import Dict, Optional
import secrets
from datetime import datetime, timedelta
import pyodbc
from cryptography.fernet import Fernet
import hashlib
import json
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from googleapiclient.errors import HttpError
from starlette.applications import Starlette
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.routing import Route, Mount
from starlette.requests import Request as StarletteRequest
import urllib.parse
import html
import re
from functools import lru_cache
from contextlib import asynccontextmanager

load_dotenv()

# Environment variables with validation
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
AZURE_SQL_SERVER = os.getenv("AZURE_SQL_SERVER")
AZURE_SQL_DATABASE = os.getenv("AZURE_SQL_DATABASE")
AZURE_SQL_USERNAME = os.getenv("AZURE_SQL_USERNAME")
AZURE_SQL_PASSWORD = os.getenv("AZURE_SQL_PASSWORD")
DEFAULT_TIMEZONE = os.getenv("DEFAULT_TIMEZONE", "America/New_York")

# Validate all required environment variables individually at startup
missing_vars = []
if not CLIENT_ID:
    missing_vars.append("GOOGLE_CLIENT_ID")
if not CLIENT_SECRET:
    missing_vars.append("GOOGLE_CLIENT_SECRET")
if not REDIRECT_URI:
    missing_vars.append("GOOGLE_REDIRECT_URI")
if not AZURE_SQL_SERVER:
    missing_vars.append("AZURE_SQL_SERVER")
if not AZURE_SQL_DATABASE:
    missing_vars.append("AZURE_SQL_DATABASE")
if not AZURE_SQL_USERNAME:
    missing_vars.append("AZURE_SQL_USERNAME")
if not AZURE_SQL_PASSWORD:
    missing_vars.append("AZURE_SQL_PASSWORD")

if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Encryption key for tokens
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("WARNING: No ENCRYPTION_KEY found, generating temporary key (DO NOT USE IN PRODUCTION)")
    ENCRYPTION_KEY = Fernet.generate_key()
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

cipher_suite = Fernet(ENCRYPTION_KEY)

SCOPES = [
    "openid",  # REQUIRED for ID token
    "https://www.googleapis.com/auth/userinfo.email",  # REQUIRED for email in ID token
    "https://www.googleapis.com/auth/userinfo.profile",  # REQUIRED for name in ID token
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/tasks"
]

# Connection pool management
connection_pool = []
MAX_POOL_SIZE = 10

"""
Database Adapter - Switches between Azure SQL and Mock Database
Add this section to your main code, replacing the database operation functions
"""
import os
from datetime import datetime, timedelta
from typing import Optional
import secrets
import hashlib

# Import mock database
from mock_database import get_mock_db

# Environment variable to enable mock database
USE_MOCK_DB = os.getenv("USE_MOCK_DB", "true").lower() == "true"

# Connection pool management (only for real DB)
connection_pool = []
MAX_POOL_SIZE = 10

def get_db_connection():
    """Create a connection to Azure SQL Database - only called when USE_MOCK_DB=false"""
    if USE_MOCK_DB:
        return None
    
    # Try to reuse existing connection from pool
    while connection_pool:
        conn = connection_pool.pop()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            return conn
        except:
            try:
                conn.close()
            except:
                pass
    
    # No valid connections in pool, create new one
    import pyodbc
    server = AZURE_SQL_SERVER
    if not server.endswith('.database.windows.net'):
        if server.startswith('tcp:'):
            server = server.replace('tcp:', '')
        if not server.endswith('.database.windows.net'):
            server = f"{server}.database.windows.net"
    else:
        server = server.replace('tcp:', '')
    
    conn_str = (
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={server};"
        f"DATABASE={AZURE_SQL_DATABASE};"
        f"UID={AZURE_SQL_USERNAME};"
        f"PWD={AZURE_SQL_PASSWORD};"
        "Encrypt=yes;"
        "TrustServerCertificate=no;"
        "Connection Timeout=30;"
    )
    
    try:
        conn = pyodbc.connect(conn_str)
        return conn
    except pyodbc.Error as e:
        print(f"Database connection failed: {e}")
        raise

def return_connection(conn):
    """Return connection to pool - only for real DB"""
    if USE_MOCK_DB or conn is None:
        return
    
    if len(connection_pool) < MAX_POOL_SIZE:
        connection_pool.append(conn)
    else:
        try:
            conn.close()
        except:
            pass

# Security helper functions (unchanged)
def encrypt_token(token_data: dict) -> str:
    """Encrypt token data for storage"""
    import json
    from cryptography.fernet import Fernet
    json_data = json.dumps(token_data)
    encrypted = cipher_suite.encrypt(json_data.encode())
    return encrypted.decode()

def decrypt_token(encrypted_data: str) -> dict:
    """Decrypt token data from storage"""
    import json
    from cryptography.fernet import Fernet
    decrypted = cipher_suite.decrypt(encrypted_data.encode())
    return json.loads(decrypted.decode())

async def verify_email(email: Optional[str]) -> Optional[str]:
    """Verify email and return user_id if user exists and has valid tokens"""
    if not email:
        return None
    
    # Sanitize email
    email = email.lower().strip()
    
    # Get user by email
    user = get_user_by_email(email)
    if not user:
        return None
    
    # Check if user is active
    if not user.get("is_active"):
        return None
    
    return user["user_id"]

def sanitize_drive_query(query: str) -> str:
    """Sanitize query string for Google Drive API by escaping special characters"""
    # Escape single quotes and backslashes for Drive API
    return query.replace("\\", "\\\\").replace("'", "\\'")

def get_user_id_by_email(email: str) -> Optional[str]:
    """Get user_id from email - lightweight lookup"""
    if not email:
        return None
    
    email = email.lower().strip()
    
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        user = mock_db.get_user_by_email(email)
        return user["user_id"] if user else None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = ? AND is_active = 1", (email,))
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        cursor.close()
        return_connection(conn)

# ===== ADAPTED DATABASE OPERATIONS =====

def create_user(email: str, display_name: str) -> str:
    """Create a new user and return user_id (NO API KEY)"""
    
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        user_id = mock_db.create_user(email, display_name)
        return user_id
    
    # Real database implementation
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        user_id = secrets.token_urlsafe(16)
        
        cursor.execute("""
            INSERT INTO users (user_id, email, display_name, created_at, last_login, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, email, display_name, datetime.utcnow(), datetime.utcnow(), 1))
        
        conn.commit()
        return user_id
    finally:
        cursor.close()
        return_connection(conn)

def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email"""
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        return mock_db.get_user_by_email(email)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT user_id, email, display_name, is_active FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        
        if row:
            return {
                "user_id": row[0],
                "email": row[1],
                "display_name": row[2],
                "is_active": bool(row[3])
            }
        return None
    finally:
        cursor.close()
        return_connection(conn)

def store_tokens(user_id: str, token_data: dict, scopes: list):
    """Store or update tokens for a user"""
    expires_in = token_data.get("expires_in", 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    scopes_str = " ".join(scopes)
    
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        encrypted_access = encrypt_token({"token": token_data.get("access_token")})
        encrypted_refresh = encrypt_token({"token": token_data.get("refresh_token")})
        mock_db.store_tokens(user_id, encrypted_access, encrypted_refresh, token_expiry, scopes_str)
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        encrypted_access = encrypt_token({"token": token_data.get("access_token")})
        encrypted_refresh = encrypt_token({"token": token_data.get("refresh_token")})
        
        cursor.execute("SELECT user_id FROM tokens WHERE user_id = ?", (user_id,))
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute("""
                UPDATE tokens
                SET access_token = ?, refresh_token = ?, token_expiry = ?, scopes = ?, updated_at = ?
                WHERE user_id = ?
            """, (encrypted_access, encrypted_refresh, token_expiry, scopes_str, datetime.utcnow(), user_id))
        else:
            cursor.execute("""
                INSERT INTO tokens (user_id, access_token, refresh_token, token_expiry, scopes, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, encrypted_access, encrypted_refresh, token_expiry, scopes_str, datetime.utcnow()))
        
        conn.commit()
    finally:
        cursor.close()
        return_connection(conn)

def get_user_tokens(user_id: str) -> Optional[dict]:
    """Get decrypted tokens for a user"""
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        token_data = mock_db.get_user_tokens(user_id)
        if token_data:
            access_token_data = decrypt_token(token_data.get("access_token"))
            refresh_token_data = decrypt_token(token_data.get("refresh_token"))
            return {
                "access_token": access_token_data.get("token"),
                "refresh_token": refresh_token_data.get("token"),
                "token_expiry": token_data.get("token_expiry"),
                "scopes": token_data.get("scopes")
            }
        return None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT access_token, refresh_token, token_expiry, scopes
            FROM tokens
            WHERE user_id = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        
        if row:
            access_token_data = decrypt_token(row[0])
            refresh_token_data = decrypt_token(row[1])
            
            return {
                "access_token": access_token_data.get("token"),
                "refresh_token": refresh_token_data.get("token"),
                "token_expiry": row[2],
                "scopes": row[3].split()
            }
        return None
    finally:
        cursor.close()
        return_connection(conn)

def create_session(user_id: str, ip_address: str, user_agent: str) -> str:
    """Create a new session and return session token"""
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=30)
    
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        mock_db.create_session(user_id, session_token, expires_at, ip_address, user_agent)
        return session_token
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO sessions (session_token, user_id, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_token, user_id, datetime.utcnow(), expires_at, ip_address, user_agent))
        
        conn.commit()
        return session_token
    finally:
        cursor.close()
        return_connection(conn)

def get_user_from_session(session_token: str) -> Optional[str]:
    """Get user_id from session token if valid"""
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        return mock_db.get_user_from_session(session_token)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT user_id FROM sessions
            WHERE session_token = ? AND expires_at > ?
        """, (session_token, datetime.utcnow()))
        
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        cursor.close()
        return_connection(conn)

def log_action(user_id: str, action: str, success: bool, source: str, details: str, ip_address: str = "N/A"):
    """Log an action to the audit_logs"""
    try:
        if USE_MOCK_DB:
            mock_db = get_mock_db()
            mock_db.log_action(user_id, action, success, source, details, ip_address)
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            if len(details) > 1024:
                details = details[:1021] + "..."
            
            success_int = 1 if success else 0
            timestamp = datetime.utcnow()
                
            cursor.execute("""
                INSERT INTO audit_logs (user_id, action, timestamp, success, ip_address, source, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, action, timestamp, success_int, ip_address, source, details))
            
            conn.commit()
        finally:
            cursor.close()
            return_connection(conn)
    except Exception as e:
        print(f"Failed to log action: {e}")

def update_last_login(user_id: str):
    """Update user's last login timestamp"""
    if USE_MOCK_DB:
        mock_db = get_mock_db()
        mock_db.update_last_login(user_id)
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET last_login = ? WHERE user_id = ?", (datetime.utcnow(), user_id))
        conn.commit()
    finally:
        cursor.close()
        return_connection(conn)

# Credentials helper with automatic token refresh
def _get_credentials(user_id: str):
    """Helper to create Google credentials from user's stored token with auto-refresh"""
    from google.oauth2.credentials import Credentials
    
    token_data = get_user_tokens(user_id)
    if not token_data:
        return None
    
    creds = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=token_data.get("scopes", SCOPES),
    )
    
    # Check if token needs refresh
    if creds.expired and creds.refresh_token:
        from google.auth.transport.requests import Request
        try:
            creds.refresh(Request())
            # Store refreshed token
            new_token_data = {
                "access_token": creds.token,
                "refresh_token": creds.refresh_token,
                "expires_in": (creds.expiry - datetime.utcnow()).total_seconds() if creds.expiry else 3600
            }
            store_tokens(user_id, new_token_data, creds.scopes)
        except Exception as e:
            print(f"Token refresh failed for user {user_id}: {e}")
    
    return creds

# --- MCP SETUP ---
mcp = FastMCP("Google Drive, Gmail, Calendar & Tasks MCP")

# --- HELPER FUNCTIONS ---

async def _read_file_content_helper(user_id: str, file_id: str) -> dict:
    """Helper function to read file content - used by multiple tools"""
    try:
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload

        creds = _get_credentials(user_id)
        service = build("drive", "v3", credentials=creds)
        
        file_metadata = service.files().get(
            fileId=file_id,
            fields="id,name,mimeType,size,modifiedTime,webViewLink"
        ).execute()
        
        mime_type = file_metadata.get("mimeType", "")
        
        if mime_type.startswith("application/vnd.google-apps"):
            export_formats = {
                "application/vnd.google-apps.document": "text/plain",
                "application/vnd.google-apps.spreadsheet": "text/csv",
                "application/vnd.google-apps.presentation": "text/plain",
            }
            
            if mime_type in export_formats:
                request = service.files().export_media(
                    fileId=file_id,
                    mimeType=export_formats[mime_type]
                )
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                
                content = fh.getvalue().decode("utf-8", errors="replace")
                return {
                    "success": True,
                    "user_id": user_id,
                    "file_id": file_id,
                    "name": file_metadata["name"],
                    "mimeType": mime_type,
                    "exported_as": export_formats[mime_type],
                    "size": len(content),
                    "content": content
                }
            else:
                return {
                    "success": False,
                    "error": f"Google Workspace file type '{mime_type}' cannot be exported as text",
                    "file_id": file_id,
                    "name": file_metadata["name"],
                    "webViewLink": file_metadata.get("webViewLink")
                }
        
        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        
        done = False
        while not done:
            status, done = downloader.next_chunk()
        
        content_bytes = fh.getvalue()
        
        text_mime_types = [
            "text/", "application/json", "application/xml",
            "application/javascript", "application/x-python"
        ]
        
        if any(mime_type.startswith(t) for t in text_mime_types):
            try:
                content = content_bytes.decode("utf-8")
                return {
                    "success": True,
                    "user_id": user_id,
                    "file_id": file_id,
                    "name": file_metadata["name"],
                    "mimeType": mime_type,
                    "size": len(content_bytes),
                    "content": content
                }
            except UnicodeDecodeError:
                pass
        
        return {
            "success": True,
            "user_id": user_id,
            "file_id": file_id,
            "name": file_metadata["name"],
            "mimeType": mime_type,
            "size": file_metadata.get("size"),
            "content": None,
            "message": "Binary file - content not displayed.",
            "webViewLink": file_metadata.get("webViewLink")
        }
        
    except Exception as e:
        return {"error": str(e), "user_id": user_id, "file_id": file_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def check_google_auth(email: str) -> dict:
    """
    Check if a user has authenticated with Google.
    Returns authentication status and auth_url if needed.
    The AI Agent should call this first before using other tools.
    """
    if not email:
        return {"error": "Email is required"}
    
    # Sanitize email
    email = email.lower().strip()
    
    try:
        # Check if user exists
        user = get_user_by_email(email)
        
        if not user:
            # User doesn't exist - need to complete OAuth
            auth_url = f"{REDIRECT_URI.rsplit('/', 1)[0]}/auth?email={urllib.parse.quote(email)}"
            
            log_action("N/A", "check_google_auth", False, "mcp_tool", f"New user: {email}")
            return {
                "authenticated": False,
                "email": email,
                "message": "User not found. Please complete Google OAuth authentication.",
                "auth_url": auth_url,
                "next_step": "User must visit auth_url to grant Google permissions"
            }
        
        # User exists - check for valid tokens
        user_id = user["user_id"]
        token_data = get_user_tokens(user_id)
        
        if not token_data:
            # User exists but no tokens
            auth_url = f"{REDIRECT_URI.rsplit('/', 1)[0]}/auth?email={urllib.parse.quote(email)}"
            
            log_action(user_id, "check_google_auth", False, "mcp_tool", f"No tokens: {email}")
            return {
                "authenticated": False,
                "email": email,
                "user_id": user_id,
                "message": "User found but not authenticated with Google. Please complete OAuth.",
                "auth_url": auth_url,
                "next_step": "User must visit auth_url to grant Google permissions"
            }
        
        # User is fully authenticated
        token_expiry = token_data.get("token_expiry")
        expiry_str = token_expiry.isoformat() if token_expiry else None
        
        log_action(user_id, "check_google_auth", True, "mcp_tool", f"Authenticated: {email}")
        return {
            "authenticated": True,
            "email": email,
            "user_id": user_id,
            "display_name": user.get("display_name"),
            "scopes": token_data.get("scopes", []),
            "token_expiry": expiry_str,
            "message": "User is authenticated. You can now use Google Drive, Gmail, Calendar, and Tasks tools."
        }
        
    except Exception as e:
        log_action("N/A", "check_google_auth", False, "mcp_tool", str(e))
        return {
            "authenticated": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }

# --- DRIVE TOOLS ---

@mcp.tool()
async def list_drive_files(email: str, max_results: int = 20) -> dict:
    """List files from Google Drive"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build

        max_results = min(max_results, 100)
        creds = _get_credentials(user_id)
        service = build("drive", "v3", credentials=creds)
        
        res = service.files().list(
            pageSize=max_results, 
            fields="files(id,name,mimeType,modifiedTime,size)"
        ).execute()
        
        files = res.get("files", [])
        log_action(user_id, "list_drive_files", True, "mcp_tool", f"Found {len(files)} files")
        return {
            "success": True,
            "user_id": user_id,
            "count": len(files),
            "files": files
        }
    except Exception as e:
        log_action(user_id, "list_drive_files", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def search_drive_files(email: str, query: str, max_results: int = 10) -> dict:
    """Search for files in Google Drive by name"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build

        creds = _get_credentials(user_id)
        service = build("drive", "v3", credentials=creds)
        
        # Use proper Drive API query escaping
        safe_query = sanitize_drive_query(query)
        res = service.files().list(
            q=f"name contains '{safe_query}'",
            pageSize=min(max_results, 100),
            fields="files(id,name,mimeType,modifiedTime,size)"
        ).execute()
        
        files = res.get("files", [])
        log_action(user_id, "search_drive_files", True, "mcp_tool", f"Query: {query}, Found: {len(files)}")
        return {
            "success": True,
            "user_id": user_id,
            "query": query,
            "count": len(files),
            "files": files
        }
    except Exception as e:
        log_action(user_id, "search_drive_files", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def read_file_by_name(email: str, file_name: str) -> dict:
    """Read the contents of a file from Google Drive by searching for its name"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build

        creds = _get_credentials(user_id)
        service = build("drive", "v3", credentials=creds)
        
        # Use proper Drive API query escaping
        safe_name = sanitize_drive_query(file_name)
        res = service.files().list(
            q=f"name = '{safe_name}'",
            pageSize=5,
            fields="files(id,name)"
        ).execute()
        
        files = res.get("files", [])
        if not files:
            log_action(user_id, "read_file_by_name", False, "mcp_tool", f"File not found: {file_name}")
            return {"error": "File not found", "user_id": user_id, "searched_for": file_name}
        
        file_id = files[0]["id"]
        
        if len(files) > 1:
            match_info = {
                "note": f"Found {len(files)} matching files, reading the first one: '{files[0]['name']}'",
                "other_matches": [{"id": f["id"], "name": f["name"]} for f in files[1:]]
            }
        else:
            match_info = {}
            
        result = await _read_file_content_helper(user_id, file_id)
        result.update(match_info)
        log_action(user_id, "read_file_by_name", True, "mcp_tool", f"File: {file_name}")
        return result
        
    except Exception as e:
        log_action(user_id, "read_file_by_name", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "searched_for": file_name, "traceback": traceback.format_exc()}

@mcp.tool()
async def read_file_content(email: str, file_id: str) -> dict:
    """Read the contents of a specific file from Google Drive"""
    # Implementation unchanged
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}
    
    try:
        result = await _read_file_content_helper(user_id, file_id)
        log_action(user_id, "read_file_content", True, "mcp_tool", f"File: {file_id}")
        return result
    except Exception as e:
        log_action(user_id, "read_file_content", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "file_id": file_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def update_document_content(email: str, file_id: str, new_content: str) -> dict:
    """Update the contents of a Google Docs document"""
    # Implementation unchanged
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError

        creds = _get_credentials(user_id)
        drive_service = build("drive", "v3", credentials=creds)
        docs_service = build("docs", "v1", credentials=creds)
        
        file_metadata = drive_service.files().get(
            fileId=file_id,
            fields="name,mimeType"
        ).execute()
        
        if file_metadata.get("mimeType") != "application/vnd.google-apps.document":
            log_action(user_id, "update_document_content", False, "mcp_tool", "File is not a Google Doc")
            return {"error": "File is not a Google Doc", "user_id": user_id, "file_id": file_id, "mimeType": file_metadata.get("mimeType")}

        doc = docs_service.documents().get(documentId=file_id).execute()
        content_length = doc.get("body", {}).get("content", [])[-1].get("endIndex", 1) - 1

        requests_payload = []
        if content_length > 1:
            requests_payload.append({
                'deleteContentRange': {
                    'range': {
                        'startIndex': 1,
                        'endIndex': content_length
                    }
                }
            })
        
        requests_payload.append({
            'insertText': {
                'location': {
                    'index': 1
                },
                'text': new_content
            }
        })
        
        result = docs_service.documents().batchUpdate(
            documentId=file_id,
            body={'requests': requests_payload}
        ).execute()
        
        log_action(user_id, "update_document_content", True, "mcp_tool", f"File: {file_id}")
        return {
            "success": True,
            "user_id": user_id,
            "file_id": file_id,
            "name": file_metadata["name"],
            "message": "Document updated successfully",
            "content_length": len(new_content)
        }

    except HttpError as e:
        log_action(user_id, "update_document_content", False, "mcp_tool", str(e))
        return {
            "error_type": "HttpError",
            "status_code": e.resp.status,
            "error": str(e),
            "user_id": user_id,
            "file_id": file_id
        }
    except Exception as e:
        log_action(user_id, "update_document_content", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def update_document_by_name(email: str, file_name: str, new_content: str) -> dict:
    """Update the contents of a Google Docs document by searching for its name"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build

        creds = _get_credentials(user_id)
        service = build("drive", "v3", credentials=creds)
        
        safe_name = sanitize_drive_query(file_name)
        res = service.files().list(
            q=f"name = '{safe_name}' and mimeType = 'application/vnd.google-apps.document'",
            pageSize=5,
            fields="files(id,name)"
        ).execute()
        
        files = res.get("files", [])
        if not files:
            log_action(user_id, "update_document_by_name", False, "mcp_tool", f"Doc not found: {file_name}")
            return {"error": "Google Doc not found", "user_id": user_id, "searched_for": file_name}
        
        file_id = files[0]["id"]
        
        if len(files) > 1:
            match_info = {
                "note": f"Found {len(files)} matching docs, updating the first one: '{files[0]['name']}'"
            }
        else:
            match_info = {}
            
        result = await update_document_content(email=email, file_id=file_id, new_content=new_content)
        result.update(match_info)
        return result
        
    except Exception as e:
        log_action(user_id, "update_document_by_name", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "searched_for": file_name, "traceback": traceback.format_exc()}

# --- GMAIL TOOLS ---

def extract_email_body(payload):
    """Extract email body with fallback to HTML if plain text not available"""
    # Try to get plain text first
    if payload.get("mimeType") == "text/plain":
        body_data = payload.get("body", {}).get("data")
        if body_data:
            return base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
    
    # Try HTML if plain text not available
    if payload.get("mimeType") == "text/html":
        body_data = payload.get("body", {}).get("data")
        if body_data:
            html_content = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
            # Strip HTML tags for better readability
            text = re.sub('<[^<]+?>', '', html_content)
            # Decode HTML entities
            text = html.unescape(text)
            return text
    
    # Recursively check parts for multipart messages
    if "parts" in payload:
        for part in payload["parts"]:
            body = extract_email_body(part)
            if body:
                return body
    
    return None

async def _list_emails_helper(user_id: str, query: Optional[str] = None, max_results: int = 20) -> dict:
    """Helper for list_emails and search_emails"""
    try:
        from googleapiclient.discovery import build
        
        max_results = min(max_results, 100)
        creds = _get_credentials(user_id)
        service = build("gmail", "v1", credentials=creds)
        
        list_params = {
            "userId": "me",
            "maxResults": max_results
        }
        if query:
            list_params["q"] = query
            
        results = service.users().messages().list(**list_params).execute()
        messages = results.get("messages", [])
        
        if not messages:
            return {
                "success": True,
                "user_id": user_id,
                "count": 0,
                "query": query if query else "all emails",
                "emails": []
            }
            
        email_list = []
        
        for msg in messages:
            msg_data = service.users().messages().get(
                userId="me", 
                id=msg["id"], 
                format="metadata", 
                metadataHeaders=["From", "To", "Subject", "Date"]
            ).execute()
            
            headers = {h["name"]: h["value"] for h in msg_data["payload"]["headers"]}
            email_list.append({
                "id": msg_data["id"],
                "threadId": msg_data["threadId"],
                "snippet": msg_data.get("snippet", ""),
                "from": headers.get("From", "Unknown"),
                "to": headers.get("To", ""),
                "subject": headers.get("Subject", "(No subject)"),
                "date": headers.get("Date", ""),
                "labels": msg_data.get("labelIds", [])
            })
            
        return {
            "success": True,
            "user_id": user_id,
            "count": len(email_list),
            "query": query if query else "all emails",
            "emails": email_list
        }
    except Exception as e:
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def list_emails(email: str, max_results: int = 20) -> dict:
    """List recent emails from Gmail"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}
    
    result = await _list_emails_helper(user_id, max_results=max_results)
    if "error" not in result:
        log_action(user_id, "list_emails", True, "mcp_tool", f"Found {result.get('count')} emails")
    else:
        log_action(user_id, "list_emails", False, "mcp_tool", result.get("error"))
    return result

@mcp.tool()
async def search_emails(email: str, query: str, max_results: int = 20) -> dict:
    """Search for emails in Gmail"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}
        
    result = await _list_emails_helper(user_id, query=query, max_results=max_results)
    if "error" not in result:
        log_action(user_id, "search_emails", True, "mcp_tool", f"Query: {query}, Found: {result.get('count')}")
    else:
        log_action(user_id, "search_emails", False, "mcp_tool", result.get("error"))
    return result

@mcp.tool()
async def read_email(email: str, email_id: str) -> dict:
    """Read the full body of a specific email"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build

        creds = _get_credentials(user_id)
        service = build("gmail", "v1", credentials=creds)
        
        message = service.users().messages().get(
            userId="me", 
            id=email_id,
            format="full"
        ).execute()
        
        headers = {h["name"]: h["value"] for h in message["payload"]["headers"]}
        
        # Use improved body extraction with HTML fallback
        body = extract_email_body(message.get("payload", {}))
        
        log_action(user_id, "read_email", True, "mcp_tool", f"Email: {email_id}")
        return {
            "success": True,
            "user_id": user_id,
            "id": message["id"],
            "threadId": message["threadId"],
            "labels": message.get("labelIds", []),
            "from": headers.get("From", "Unknown"),
            "to": headers.get("To", ""),
            "cc": headers.get("Cc", ""),
            "subject": headers.get("Subject", "(No subject)"),
            "date": headers.get("Date", ""),
            "snippet": message.get("snippet", ""),
            "body": body if body else ""
        }
    except Exception as e:
        log_action(user_id, "read_email", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "email_id": email_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def send_email(
    email: str,
    to: str,
    subject: str,
    body: str,
    cc: Optional[str] = None,
    bcc: Optional[str] = None
) -> dict:
    """Send an email"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("gmail", "v1", credentials=creds)
        
        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        if cc:
            message["cc"] = cc
        if bcc:
            message["bcc"] = bcc
            
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        
        send_message_request = {
            "raw": raw_message
        }
        
        sent_message = service.users().messages().send(
            userId="me",
            body=send_message_request
        ).execute()
        
        log_action(user_id, "send_email", True, "mcp_tool", f"To: {to}, Subject: {subject}")
        return {
            "success": True,
            "user_id": user_id,
            "message_id": sent_message["id"],
            "thread_id": sent_message["threadId"],
            "to": to,
            "subject": subject
        }
    except Exception as e:
        log_action(user_id, "send_email", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def mark_email_as_read(email: str, email_id: str) -> dict:
    """Mark an email as read (removes the UNREAD label)"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("gmail", "v1", credentials=creds)
        
        service.users().messages().modify(
            userId="me",
            id=email_id,
            body={"removeLabelIds": ["UNREAD"]}
        ).execute()
        
        log_action(user_id, "mark_email_as_read", True, "mcp_tool", f"Email: {email_id}")
        return {
            "success": True,
            "user_id": user_id,
            "email_id": email_id,
            "message": "Email marked as read"
        }
    except Exception as e:
        log_action(user_id, "mark_email_as_read", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "email_id": email_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def mark_email_as_unread(email: str, email_id: str) -> dict:
    """Mark an email as unread (adds the UNREAD label)"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("gmail", "v1", credentials=creds)
        
        service.users().messages().modify(
            userId="me",
            id=email_id,
            body={"addLabelIds": ["UNREAD"]}
        ).execute()
        
        log_action(user_id, "mark_email_as_unread", True, "mcp_tool", f"Email: {email_id}")
        return {
            "success": True,
            "user_id": user_id,
            "email_id": email_id,
            "message": "Email marked as unread"
        }
    except Exception as e:
        log_action(user_id, "mark_email_as_unread", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "email_id": email_id, "traceback": traceback.format_exc()}


# --- GOOGLE CALENDAR TOOLS ---

@mcp.tool()
async def list_calendar_events(
    email: str,
    max_results: int = 10,
    calendar_id: str = "primary",
    timezone: str = None
) -> dict:
    """List upcoming events from Google Calendar"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        from datetime import datetime, timezone as tz

        creds = _get_credentials(user_id)
        service = build("calendar", "v3", credentials=creds)
        
        now = datetime.now(tz.utc).isoformat()
        
        events_result = service.events().list(
            calendarId=calendar_id,
            timeMin=now,
            maxResults=max_results,
            singleEvents=True,
            orderBy="startTime"
        ).execute()
        
        events = events_result.get("items", [])
        event_list = []
        
        for event in events:
            start = event["start"].get("dateTime", event["start"].get("date"))
            end = event["end"].get("dateTime", event["end"].get("date"))
            event_list.append({
                "id": event["id"],
                "summary": event.get("summary", "(No title)"),
                "description": event.get("description", ""),
                "location": event.get("location", ""),
                "start": start,
                "end": end,
                "status": event.get("status", ""),
                "htmlLink": event.get("htmlLink", ""),
                "attendees": [
                    {"email": a.get("email"), "responseStatus": a.get("responseStatus")}
                    for a in event.get("attendees", [])
                ]
            })
            
        log_action(user_id, "list_calendar_events", True, "mcp_tool", f"Found {len(event_list)} events")
        return {
            "success": True,
            "user_id": user_id,
            "count": len(event_list),
            "calendar_id": calendar_id,
            "events": event_list
        }
    except Exception as e:
        log_action(user_id, "list_calendar_events", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def create_calendar_event(
    email: str,
    summary: str,
    start_time: str,
    end_time: str,
    description: str = "",
    location: str = "",
    attendees: str = "",
    calendar_id: str = "primary",
    timezone: str = None
) -> dict:
    """Create a new event in Google Calendar"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        # Use provided timezone or default
        tz = timezone or DEFAULT_TIMEZONE
        
        creds = _get_credentials(user_id)
        service = build("calendar", "v3", credentials=creds)
        
        event = {
            "summary": summary,
            "description": description,
            "location": location,
        }
        
        # Handle all-day vs. dateTime
        if "T" in start_time:
            event["start"] = {"dateTime": start_time, "timeZone": tz}
        else:
            event["start"] = {"date": start_time}
            
        if "T" in end_time:
            event["end"] = {"dateTime": end_time, "timeZone": tz}
        else:
            event["end"] = {"date": end_time}
            
        if attendees:
            # CHANGE: Use different variable name to avoid collision
            event["attendees"] = [{"email": attendee_email.strip()} for attendee_email in attendees.split(",")]
            
        created_event = service.events().insert(
            calendarId=calendar_id,
            body=event,
            sendUpdates="all"
        ).execute()
        
        log_action(user_id, "create_calendar_event", True, "mcp_tool", f"Event: {summary}")
        return {
            "success": True,
            "user_id": user_id,
            "event_id": created_event["id"],
            "summary": created_event.get("summary"),
            "start": created_event["start"].get("dateTime", created_event["start"].get("date")),
            "end": created_event["end"].get("dateTime", created_event["end"].get("date")),
            "htmlLink": created_event.get("htmlLink")
        }
    except Exception as e:
        log_action(user_id, "create_calendar_event", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def update_calendar_event(
    email: str,
    event_id: str,
    summary: str = "",
    start_time: str = "",
    end_time: str = "",
    description: str = "",
    location: str = "",
    calendar_id: str = "primary",
    timezone: str = None
) -> dict:
    """Update an existing event in Google Calendar"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        # Use provided timezone or default
        tz = timezone or DEFAULT_TIMEZONE
        
        creds = _get_credentials(user_id)
        service = build("calendar", "v3", credentials=creds)
        
        event = service.events().get(calendarId=calendar_id, eventId=event_id).execute()
        
        if summary:
            event["summary"] = summary
        if description:
            event["description"] = description
        if location:
            event["location"] = location
            
        if start_time:
            if "T" in start_time:
                event["start"] = {"dateTime": start_time, "timeZone": tz}
            else:
                event["start"] = {"date": start_time}
        
        if end_time:
            if "T" in end_time:
                event["end"] = {"dateTime": end_time, "timeZone": tz}
            else:
                event["end"] = {"date": end_time}
        
        updated_event = service.events().update(
            calendarId=calendar_id,
            eventId=event_id,
            body=event
        ).execute()
        
        log_action(user_id, "update_calendar_event", True, "mcp_tool", f"Event: {event_id}")
        return {
            "success": True,
            "user_id": user_id,
            "event_id": updated_event["id"],
            "summary": updated_event.get("summary"),
            "start": updated_event["start"].get("dateTime", updated_event["start"].get("date")),
            "end": updated_event["end"].get("dateTime", updated_event["end"].get("date")),
            "htmlLink": updated_event.get("htmlLink")
        }
    except Exception as e:
        log_action(user_id, "update_calendar_event", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "event_id": event_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def delete_calendar_event(
    email: str,
    event_id: str,
    calendar_id: str = "primary"
) -> dict:
    """Delete an event from Google Calendar"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("calendar", "v3", credentials=creds)
        
        service.events().delete(
            calendarId=calendar_id,
            eventId=event_id
        ).execute()
        
        log_action(user_id, "delete_calendar_event", True, "mcp_tool", f"Event: {event_id}")
        return {
            "success": True,
            "user_id": user_id,
            "event_id": event_id,
            "message": "Event deleted successfully"
        }
    except Exception as e:
        log_action(user_id, "delete_calendar_event", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "event_id": event_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def search_calendar_events(
    email: str,
    query: str,
    max_results: int = 10,
    calendar_id: str = "primary"
) -> dict:
    """Search for calendar events matching a query"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        from datetime import datetime, timezone

        creds = _get_credentials(user_id)
        service = build("calendar", "v3", credentials=creds)
        
        events_result = service.events().list(
            calendarId=calendar_id,
            maxResults=max_results,
            singleEvents=True,
            orderBy="startTime",
            timeMin=datetime.now(timezone.utc).isoformat(),
            q=query
        ).execute()
        
        events = events_result.get("items", [])
        event_list = []
        
        for event in events:
            start = event["start"].get("dateTime", event["start"].get("date"))
            end = event["end"].get("dateTime", event["end"].get("date"))
            event_list.append({
                "id": event["id"],
                "summary": event.get("summary", "(No title)"),
                "description": event.get("description", ""),
                "location": event.get("location", ""),
                "start": start,
                "end": end,
                "status": event.get("status", ""),
                "htmlLink": event.get("htmlLink")
            })
            
        log_action(user_id, "search_calendar_events", True, "mcp_tool", f"Query: {query}, Found: {len(event_list)}")
        return {
            "success": True,
            "user_id": user_id,
            "count": len(event_list),
            "query": query,
            "calendar_id": calendar_id,
            "events": event_list
        }
    except Exception as e:
        log_action(user_id, "search_calendar_events", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

# --- GOOGLE TASKS TOOLS ---

@mcp.tool()
async def list_task_lists(email: str) -> dict:
    """List all Google Tasks task lists"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("tasks", "v1", credentials=creds)
        
        results = service.tasklists().list(maxResults=100).execute()
        items = results.get("items", [])
        
        task_lists = [
            {"id": tl["id"], "title": tl["title"], "updated": tl["updated"]}
            for tl in items
        ]
        
        log_action(user_id, "list_task_lists", True, "mcp_tool", f"Found {len(task_lists)} lists")
        return {
            "success": True,
            "user_id": user_id,
            "count": len(task_lists),
            "task_lists": task_lists
        }
    except Exception as e:
        log_action(user_id, "list_task_lists", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def list_tasks(
    email: str,
    task_list_id: str = "@default",
    max_results: int = 20
) -> dict:
    """List tasks from a specific Google Tasks list"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("tasks", "v1", credentials=creds)
        
        results = service.tasks().list(
            tasklist=task_list_id,
            maxResults=max_results
        ).execute()
        
        items = results.get("items", [])
        
        formatted_tasks = []
        for task in items:
            formatted_tasks.append({
                "id": task["id"],
                "title": task.get("title", ""),
                "notes": task.get("notes", ""),
                "status": task.get("status", ""),
                "due": task.get("due", ""),
                "updated": task.get("updated", ""),
                "completed": task.get("completed", "")
            })
            
        log_action(user_id, "list_tasks", True, "mcp_tool", f"Found {len(formatted_tasks)} tasks")
        return {
            "success": True,
            "user_id": user_id,
            "count": len(formatted_tasks),
            "task_list_id": task_list_id,
            "tasks": formatted_tasks
        }
    except Exception as e:
        log_action(user_id, "list_tasks", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def create_task(
    email: str,
    title: str,
    notes: str = "",
    due: str = "",
    task_list_id: str = "@default"
) -> dict:
    """Create a new task in Google Tasks"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("tasks", "v1", credentials=creds)
        
        task = {
            "title": title,
            "notes": notes
        }
        if due:
            task["due"] = due
            
        result = service.tasks().insert(
            tasklist=task_list_id,
            body=task
        ).execute()
        
        log_action(user_id, "create_task", True, "mcp_tool", f"Task: {title}")
        
        return {
            "success": True,
            "user_id": user_id,
            "task_id": result["id"],
            "title": result["title"],
            "notes": result.get("notes", ""),
            "due": result.get("due", ""),
            "status": result.get("status", ""),
            "message": "Task created successfully"
        }
        
    except Exception as e:
        log_action(user_id, "create_task", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def create_task_from_email(email: str, email_id: str, task_list_id: str = "@default", include_snippet: bool = True, include_sender: bool = True, mark_email_done: bool = False) -> dict:
    """Create a Google Task from a Gmail email (mimics Gmail's 'Add to Tasks' button)"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build

        creds = _get_credentials(user_id)
        gmail_service = build("gmail", "v1", credentials=creds)
        tasks_service = build("tasks", "v1", credentials=creds)
        
        # Get email details with full format to extract more info
        try:
            message = gmail_service.users().messages().get(
                userId="me",
                id=email_id,
                format="full"
            ).execute()
        except HttpError as e:
            if e.resp.status == 404:
                log_action(user_id, "create_task_from_email", False, "mcp_tool", f"Email not found: {email_id}")
                return {
                    "success": False,
                    "error": f"Email not found with ID: {email_id}",
                    "hint": "Please verify the email ID is correct. Use list_emails or search_emails to get valid email IDs.",
                    "user_id": user_id,
                    "email_id": email_id
                }
            else:
                raise
        
        # Extract comprehensive headers
        headers = {h["name"]: h["value"] for h in message.get("payload", {}).get("headers", [])}
        
        subject = headers.get("Subject", "(No subject)")
        from_email = headers.get("From", "Unknown sender")
        date = headers.get("Date", "")
        to_email = headers.get("To", "")
        snippet = message.get("snippet", "")
        
        # Build task title (match Gmail's format: subject line)
        task_title = subject
        
        # Build comprehensive task notes
        task_notes_parts = []
        
        if include_sender:
            task_notes_parts.append(f"From: {from_email}")
            if to_email:
                task_notes_parts.append(f"To: {to_email}")
            if date:
                task_notes_parts.append(f"Date: {date}")
        
        if include_snippet and snippet:
            task_notes_parts.append("")  # Empty line for spacing
            task_notes_parts.append(snippet)
        
        # Always add email link (this is key to the Gmail integration)
        task_notes_parts.append("")
        email_link = f"https://mail.google.com/mail/u/0/#inbox/{email_id}"
        task_notes_parts.append(f"View email: {email_link}")
        
        task_notes = "\n".join(task_notes_parts)
        
        # Create the task
        task = {
            "title": task_title,
            "notes": task_notes
        }
        
        result = tasks_service.tasks().insert(
            tasklist=task_list_id,
            body=task
        ).execute()
        
        # Optionally mark email as read
        response_data = {
            "success": True,
            "user_id": user_id,
            "task_id": result["id"],
            "title": result["title"],
            "notes": result.get("notes", ""),
            "email_id": email_id,
            "email_subject": subject,
            "message": "Task created from email successfully"
        }
        
        if mark_email_done:
            try:
                gmail_service.users().messages().modify(
                    userId="me",
                    id=email_id,
                    body={"removeLabelIds": ["UNREAD"]}
                ).execute()
                response_data["email_marked_read"] = True
            except Exception as e:
                response_data["email_mark_warning"] = f"Task created but couldn't mark email as read: {str(e)}"
        
        log_action(user_id, "create_task_from_email", True, "mcp_tool", f"Email: {email_id} -> Task: {result['id']}")
        return response_data
        
    except HttpError as e:
        log_action(user_id, "create_task_from_email", False, "mcp_tool", f"HttpError: {str(e)}")
        return {
            "success": False,
            "error": f"Gmail API error: {e.resp.status} - {e.resp.reason}",
            "details": str(e),
            "user_id": user_id,
            "email_id": email_id,
            "traceback": traceback.format_exc()
        }
    except Exception as e:
        log_action(user_id, "create_task_from_email", False, "mcp_tool", str(e))
        return {
            "success": False,
            "error": str(e), 
            "user_id": user_id,
            "email_id": email_id, 
            "traceback": traceback.format_exc()
        }
    
@mcp.tool()
async def add_emails_to_tasks(
    email: str,
    email_ids: str,
    task_list_id: str = "@default",
    mark_emails_done: bool = False
) -> dict:
    """Create Google Tasks from multiple Gmail emails at once (bulk operation)"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    # Split email IDs
    ids_list = [id.strip() for id in email_ids.split(",") if id.strip()]
    
    if not ids_list:
        log_action(user_id, "add_emails_to_tasks", False, "mcp_tool", "No valid email IDs provided")
        return {
            "success": False,
            "error": "No valid email IDs provided",
            "user_id": user_id
        }
    
    results = []
    success_count = 0
    error_count = 0
    
    # Process each email
    for email_id in ids_list:
        result = await create_task_from_email(
            email=email,
            email_id=email_id,
            task_list_id=task_list_id,
            mark_email_done=mark_emails_done
        )
        
        if result.get("success"):
            success_count += 1
        else:
            error_count += 1
        
        results.append({
            "email_id": email_id,
            "result": result
        })
    
    log_action(user_id, "add_emails_to_tasks", True, "mcp_tool", 
               f"Processed {len(ids_list)} emails: {success_count} success, {error_count} errors")
    
    return {
        "success": success_count > 0,
        "user_id": user_id,
        "total_processed": len(ids_list),
        "success_count": success_count,
        "error_count": error_count,
        "results": results
    }


@mcp.tool()
async def create_task_from_email_search(
    email: str,
    search_query: str,
    max_emails: int = 5,
    task_list_id: str = "@default",
    mark_emails_done: bool = False
) -> dict:
    """Search for emails and create tasks from all matching results"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    # First, search for emails
    max_emails = min(max_emails, 20)
    search_result = await search_emails(email=email, query=search_query, max_results=max_emails)
    
    if not search_result.get("success"):
        log_action(user_id, "create_task_from_email_search", False, "mcp_tool", 
                   f"Search failed: {search_query}")
        return {
            "success": False,
            "error": "Failed to search emails",
            "user_id": user_id,
            "details": search_result
        }
    
    emails = search_result.get("emails", [])
    
    if not emails:
        log_action(user_id, "create_task_from_email_search", False, "mcp_tool", 
                   f"No emails found: {search_query}")
        return {
            "success": False,
            "error": f"No emails found matching query: {search_query}",
            "user_id": user_id,
            "query": search_query
        }
    
    # Extract email IDs
    email_ids = [email["id"] for email in emails]
    
    # Use bulk add function
    result = await add_emails_to_tasks(
        email=email,
        email_ids=",".join(email_ids),
        task_list_id=task_list_id,
        mark_emails_done=mark_emails_done
    )
    
    result["search_query"] = search_query
    result["emails_found"] = len(emails)
    
    log_action(user_id, "create_task_from_email_search", True, "mcp_tool", 
               f"Query: {search_query}, Found: {len(emails)}, Created: {result.get('success_count')}")
    
    return result

@mcp.tool()
async def update_task(
    email: str,
    task_id: str,
    title: str = "",
    notes: str = "",
    due: str = "",
    task_list_id: str = "@default"
) -> dict:
    """Update an existing task in Google Tasks"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("tasks", "v1", credentials=creds)
        
        task = service.tasks().get(tasklist=task_list_id, task=task_id).execute()
        
        if title:
            task["title"] = title
        if notes:
            task["notes"] = notes
        if due:
            task["due"] = due
        
        result = service.tasks().update(
            tasklist=task_list_id,
            task=task_id,
            body=task
        ).execute()
        
        log_action(user_id, "update_task", True, "mcp_tool", f"Task: {task_id}")
        return {
            "success": True,
            "user_id": user_id,
            "task_id": result["id"],
            "title": result["title"],
            "notes": result.get("notes", ""),
            "due": result.get("due", ""),
            "status": result.get("status", "")
        }
    except Exception as e:
        log_action(user_id, "update_task", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "task_id": task_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def complete_task(
    email: str,
    task_id: str,
    task_list_id: str = "@default"
) -> dict:
    """Mark a task as completed"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("tasks", "v1", credentials=creds)
        
        task = service.tasks().get(tasklist=task_list_id, task=task_id).execute()
        task["status"] = "completed"
        
        result = service.tasks().update(
            tasklist=task_list_id,
            task=task_id,
            body=task
        ).execute()
        
        log_action(user_id, "complete_task", True, "mcp_tool", f"Task: {task_id}")
        return {
            "success": True,
            "user_id": user_id,
            "task_id": result["id"],
            "status": result["status"],
            "message": "Task marked as completed"
        }
    except Exception as e:
        log_action(user_id, "complete_task", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "task_id": task_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def delete_task(
    email: str,
    task_id: str,
    task_list_id: str = "@default"
) -> dict:
    """Delete a task from Google Tasks"""
    user_id = await verify_email(email)
    if not user_id:
        return {"error": "Invalid email or user not authenticated with Google"}

    try:
        from googleapiclient.discovery import build
        
        creds = _get_credentials(user_id)
        service = build("tasks", "v1", credentials=creds)
        
        service.tasks().delete(
            tasklist=task_list_id,
            task=task_id
        ).execute()
        
        log_action(user_id, "delete_task", True, "mcp_tool", f"Task: {task_id}")
        return {
            "success": True,
            "user_id": user_id,
            "task_id": task_id,
            "message": "Task deleted successfully"
        }
    except Exception as e:
        log_action(user_id, "delete_task", False, "mcp_tool", str(e))
        return {"error": str(e), "user_id": user_id, "task_id": task_id, "traceback": traceback.format_exc()}

@mcp.tool()
async def get_auth_status(email: str) -> dict:
    """Check the authentication status and return user info"""
    user_id = await verify_email(email)
    if not user_id:
        return {"authenticated": False, "error": "Invalid email or user not authenticated with Google"}
    
    try:
        token_data = get_user_tokens(user_id)
        if not token_data:
            return {
                "authenticated": False,
                "error": "No tokens found for user"
            }
        
        # Convert datetime to string for JSON serialization
        token_expiry = token_data.get("token_expiry")
        expiry_str = token_expiry.isoformat() if token_expiry else None
        
        return {
            "authenticated": True,
            "user_id": user_id,
            "scopes": token_data.get("scopes", []),
            "token_expiry": expiry_str
        }
    except Exception as e:
        log_action(user_id, "get_auth_status", False, "mcp_tool", str(e))
        return {
            "authenticated": False,
            "error": f"Error retrieving auth status: {str(e)}"
        }
        
# --- STARLETTE APP & OAUTH ENDPOINTS ---

# Create the MCP ASGI app with http_app() method
mcp_asgi = mcp.http_app(path='/mcp')

async def start_auth(request: StarletteRequest):
    """Start the Google OAuth2 flow with email parameter"""
    from google_auth_oauthlib.flow import Flow
    
    # Get email from query parameter
    email = request.query_params.get("email")
    
    if not email:
        return StarletteJSONResponse(
            {"error": "Email parameter is required. Use: /auth?email=user@example.com"}, 
            status_code=400
        )
    
    # Sanitize email
    email = email.lower().strip()
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    
    # Include email in state parameter so we can retrieve it in callback
    auth_url, state = flow.authorization_url(
        access_type="offline", 
        prompt="consent",
        state=email  # Pass email as state
    )
    
    log_action("N/A", "start_auth", True, "api", f"Auth started for: {email}", request.client.host)
    
    return StarletteJSONResponse({
        "auth_url": auth_url,
        "email": email,
        "message": "Visit auth_url to complete Google authentication"
    })

async def check_auth_status(request: StarletteRequest):
    """Check if a user's email is authenticated in the database"""
    try:
        # Get email from query parameter
        email = request.query_params.get("email")
        
        if not email:
            return StarletteJSONResponse(
                {"error": "Email parameter is required"}, 
                status_code=400
            )
        
        # Sanitize email
        email = email.lower().strip()
        
        # Check if user exists
        user = get_user_by_email(email)
        
        if not user:
            log_action("N/A", "check_auth_status", False, "api", f"User not found: {email}", request.client.host)
            return StarletteJSONResponse({
                "authenticated": False,
                "email": email,
                "message": "User not found - need to complete OAuth"
            })
        
        # Check if user has valid tokens
        user_id = user["user_id"]
        token_data = get_user_tokens(user_id)
        
        if not token_data:
            log_action(user_id, "check_auth_status", False, "api", f"No tokens for: {email}", request.client.host)
            return StarletteJSONResponse({
                "authenticated": False,
                "email": email,
                "user_id": user_id,
                "message": "User exists but not authenticated with Google - need OAuth"
            })
        
        # Convert datetime to string for JSON serialization
        token_expiry = token_data.get("token_expiry")
        expiry_str = token_expiry.isoformat() if token_expiry else None
        
        log_action(user_id, "check_auth_status", True, "api", f"Auth check for: {email}", request.client.host)
        return StarletteJSONResponse({
            "authenticated": True,
            "email": email,
            "user_id": user_id,
            "display_name": user.get("display_name"),
            "is_active": user.get("is_active"),
            "scopes": token_data.get("scopes", []),
            "token_expiry": expiry_str
        })
        
    except Exception as e:
        traceback.print_exc()
        log_action("N/A", "check_auth_status", False, "api", str(e), request.client.host)
        return StarletteJSONResponse(
            {"error": str(e), "traceback": traceback.format_exc()}, 
            status_code=500
        )
    
async def auth_page(request: StarletteRequest):
    """HTML page to initiate OAuth flow - requires email input"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google OAuth Authentication</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
            }
            input {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
            }
            button {
                background-color: #4285f4;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                width: 100%;
            }
            button:hover {
                background-color: #357ae8;
            }
            button:disabled {
                background-color: #ccc;
                cursor: not-allowed;
            }
            .info {
                background-color: #f0f0f0;
                padding: 15px;
                border-radius: 4px;
                margin-top: 20px;
            }
            .error {
                color: red;
                margin-top: 10px;
            }
        </style>
    </head>
    <body>
        <h1>Google OAuth Authentication</h1>
        <p>Enter your email address to authenticate with Google:</p>
        
        <input 
            type="email" 
            id="emailInput" 
            placeholder="your.email@example.com"
            autocomplete="email"
        />
        <button onclick="startAuth()" id="authButton">Authenticate with Google</button>
        <div id="errorMsg" class="error"></div>
        
        <div class="info">
            <h3>What happens next:</h3>
            <ol>
                <li>Enter your email address above</li>
                <li>Click "Authenticate with Google"</li>
                <li>You'll be redirected to Google to sign in</li>
                <li>Grant permissions to the application</li>
                <li>You'll be redirected back - all done!</li>
                <li>Use your email in MCP tools to access Google services</li>
            </ol>
        </div>
        
        <script>
            const emailInput = document.getElementById('emailInput');
            const authButton = document.getElementById('authButton');
            const errorMsg = document.getElementById('errorMsg');
            
            // Get email from URL parameter if present
            const urlParams = new URLSearchParams(window.location.search);
            const emailParam = urlParams.get('email');
            if (emailParam) {
                emailInput.value = emailParam;
            }
            
            async function startAuth() {
                const email = emailInput.value.trim();
                
                if (!email) {
                    errorMsg.textContent = 'Please enter your email address';
                    return;
                }
                
                // Basic email validation
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email)) {
                    errorMsg.textContent = 'Please enter a valid email address';
                    return;
                }
                
                errorMsg.textContent = '';
                authButton.disabled = true;
                authButton.textContent = 'Redirecting...';
                
                try {
                    const response = await fetch('/auth?email=' + encodeURIComponent(email));
                    const data = await response.json();
                    
                    if (data.error) {
                        errorMsg.textContent = 'Error: ' + data.error;
                        authButton.disabled = false;
                        authButton.textContent = 'Authenticate with Google';
                        return;
                    }
                    
                    window.location.href = data.auth_url;
                } catch (error) {
                    errorMsg.textContent = 'Error starting authentication: ' + error;
                    authButton.disabled = false;
                    authButton.textContent = 'Authenticate with Google';
                }
            }
            
            // Allow Enter key to submit
            emailInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    startAuth();
                }
            });
        </script>
    </body>
    </html>
    """
    from starlette.responses import HTMLResponse
    return HTMLResponse(content=html_content)

async def oauth_callback(request: StarletteRequest):
    """Handle the OAuth2 callback from Google - NO API KEY RETURNED"""
    from google_auth_oauthlib.flow import Flow
    import jwt

    code = request.query_params.get("code")
    state = request.query_params.get("state")  # This contains the email
    
    if not code:
        return StarletteJSONResponse({"error": "No code found in callback"}, status_code=400)
    
    if not state:
        return StarletteJSONResponse({"error": "No state (email) found in callback"}, status_code=400)
    
    # The state parameter contains the email
    email = state.lower().strip()
    
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )
        
        flow.fetch_token(code=code)
        
        creds = flow.credentials
        token_data = {
            "access_token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
            "expires_in": (creds.expiry - datetime.utcnow()).total_seconds()
        }

        # Get user info from ID token
        id_token = creds.id_token
        if not id_token:
            return StarletteJSONResponse(
                {"error": "No ID token received from Google"}, 
                status_code=500
            )
        
        # Decode the ID token
        user_info = jwt.decode(id_token, options={"verify_signature": False})
        
        token_email = user_info.get("email")
        display_name = user_info.get("name", email)
        
        if not token_email:
            return StarletteJSONResponse(
                {"error": "Could not retrieve email from ID token"}, 
                status_code=500
            )
        
        # Verify the email from token matches the email from state
        if token_email.lower() != email:
            return StarletteJSONResponse(
                {"error": f"Email mismatch: expected {email}, got {token_email}"}, 
                status_code=400
            )

        # Check if user exists, create if not
        user = get_user_by_email(email)
        if user:
            user_id = user["user_id"]
            user_existed = True
        else:
            user_id = create_user(email, display_name)
            user_existed = False
        
        # Store tokens
        store_tokens(user_id, token_data, SCOPES)
        update_last_login(user_id)
        
        # Create session
        session_token = create_session(
            user_id, 
            request.client.host, 
            request.headers.get("User-Agent", "Unknown")
        )
        
        log_action(user_id, "oauth_callback", True, "auth", f"User {email} authenticated", request.client.host)

        return StarletteJSONResponse({
            "success": True,
            "message": "Authentication successful! You can now use your email with the MCP tools.",
            "email": email,
            "user_id": user_id,
            "display_name": display_name,
            "session_token": session_token,
            "user_existed": user_existed,
            "next_step": "Use your email in MCP tool calls to access Google services"
        })

    except Exception as e:
        traceback.print_exc()
        log_action("N/A", "oauth_callback", False, "auth", str(e), request.client.host)
        return StarletteJSONResponse({
            "error": str(e), 
            "traceback": traceback.format_exc()
        }, status_code=500)

async def health(request: StarletteRequest):
    """Health check endpoint, including DB connection"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        return_connection(conn)
        db_status = "connected"
    except Exception as e:
        db_status = f"disconnected: {e}"

    return StarletteJSONResponse({
        "status": "ok",
        "database": db_status
    })

async def root(request: StarletteRequest):
    """Root endpoint with updated documentation"""
    return StarletteJSONResponse({
        "service": "Google Drive, Gmail, Calendar & Tasks MCP Server",
        "database_backend": "Azure SQL (pyodbc)" if not USE_MOCK_DB else "Mock Database",
        "authentication": "Email-based (no API keys required)",
        "endpoints": {
            "auth": "/auth?email=user@example.com - Start OAuth flow for an email",
            "start_auth_page": "/start-auth - HTML page to start OAuth (with email input)",
            "callback": "/oauth2callback - OAuth callback (handles redirect)",
            "check_auth": "/check-auth?email=user@example.com - Check if email is authenticated",
            "health": "/health - Health check (includes DB)",
            "mcp": "/mcp/ - MCP protocol endpoint (POST only)"
        },
        "available_tools": [
            "Auth: check_google_auth - Check authentication status before using other tools",
            "Drive: list_drive_files, search_drive_files, read_file_by_name, read_file_content, update_document_content, update_document_by_name",
            "Gmail: list_emails, read_email, send_email, search_emails, mark_email_as_read, mark_email_as_unread",
            "Calendar: list_calendar_events, create_calendar_event, update_calendar_event, delete_calendar_event, search_calendar_events",
            "Tasks: list_task_lists, list_tasks, create_task, create_task_from_email, add_emails_to_tasks, create_task_from_email_search, update_task, complete_task, delete_task"
        ],
        "usage": {
            "step_1": "AI Agent calls check_google_auth with user's email",
            "step_2a": "If authenticated=true, agent can use all tools with email",
            "step_2b": "If authenticated=false, user visits auth_url to complete OAuth",
            "step_3": "After OAuth, agent retries and tools work immediately",
            "note": "No API keys needed - just use email in all tool calls"
        }
    })

# Create main app using Starlette
app = Starlette(
    routes=[
        Route("/", root),
        Route("/start-auth", auth_page),
        Route("/auth", start_auth),
        Route("/oauth2callback", oauth_callback),
        Route("/check-auth", check_auth_status, methods=["GET"]),  # NEW ROUTE
        Route("/health", health),
        Mount("/", mcp_asgi),  # Mount MCP at root - it handles /mcp/ path itself
    ],
    lifespan=mcp_asgi.lifespan,  # CRITICAL: Use mcp_asgi's lifespan
)
