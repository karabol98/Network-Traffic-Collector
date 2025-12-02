import os
from typing import Dict, List, Set, Optional, Any

import bcrypt
from bucket_manager import get_bucket_manager, get_meta_indexes
from database import get_db
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from sqlalchemy.orm import Session
from fastapi import Cookie, Depends, HTTPException, Request, status
from datetime import datetime, timedelta, timezone
import jwt
import logging

from storage import get_indexes
from models import Role, RolePermission, User, UserPermission
from schemas import IndexPermission, RoleCreate, UserCreate



AUDIT_INDEX="_audit"

# Define OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Define secret key and algorithm for JWT encoding
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "MyVerySecretK3y!!") # Default to a hardcoded secret key
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256") # Default to HS256
JWT_ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRATION_TIME", "1800"))  # Default to 30 minutes
ADMIN_USER_PASSWORD= os.getenv("ADMIN_USER_PASSWORD", "Adm1n@dm1n")  # Default to 'adminadmin'
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")  # Default to 'development'

if ENVIRONMENT == "production":
    SECURE_COOKIE = True
else:
    SECURE_COOKIE = False

ADMIN_ROLE_NAME = "admin"
USER_ROLE_NAME = "user"
ADMIN_USER_USERNAME = "admin"
ADMIN_USER_EMAIL = "admin@localhost.org"


logger = logging.getLogger('uvicorn.error')

def verify_password(plain_password : str, hashed_password : str):
    """Verify if the plain password matches the hashed password."""
    logger.debug("Verifying password...")
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def hash_password(password : str) -> str:
    """Hash a plain password."""
    hash_bs = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hash_bs.decode('utf-8')

def update_password(username: str, new_password: str, db: Session) -> User|dict:
    """Update the user's password."""

    user = get_user_by_username(username, db)
    if not user:
        return {"status_code": status.HTTP_404_NOT_FOUND, "detail": "User not found."}
    if not new_password:
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "Password is required."}
    if len(new_password) < 10:
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "Password must be at least 10 characters."}

    if verify_password(new_password, user.hashed_password):
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "New password cannot be the same as the old password."}

    # Hash the new password
    hashed_password = hash_password(new_password)

    # Update the user's password in the database
    user.hashed_password = hashed_password

    # Commit the changes to the database
    db.commit()
    db.refresh(user)

    return user

# JWT token utilities
def create_user_access_token(user: User):
    """Generate a JWT token for a user."""
    data = {"sub": str(user.id), "username": user.username}
    return create_access_token(data)


# JWT token utilities
def create_access_token(data: dict, expires_delta: timedelta = timedelta(seconds=JWT_ACCESS_TOKEN_EXPIRE_SECONDS)):
    """Generate a JWT token with a given expiration time."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    """Verify the JWT token and return its payload if valid, otherwise return None."""
    try:
        logger.debug(f"Verifying Token: {token}")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError as e:
        logger.error(f"Token has expired: {e}")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return None
    except jwt.PyJWTError as e:
        logger.error("Invalid token: {e}")
        return None


def has_admin_role(user: User) -> bool:
    """
    Check if the user has the 'admin' role.
    """
    # Check if the user has the 'admin' role
    if user is None or user.roles is None:
        return False

    return any(role.name == ADMIN_ROLE_NAME for role in user.roles)


def get_all_indexes_raw(start_timestamp: datetime = None, end_timestamp: datetime = None) -> List[str]:
    indices = get_bucket_manager().get_indexes(start_timestamp, end_timestamp)
    indices.extend(get_indexes(start_timestamp, end_timestamp))
    return list(set(indices))


def filter_index_permissions(indexes: List[IndexPermission]) -> List[IndexPermission]:
    """
    Filter the indexes based on the existing indexes.
    """
    # Check if the indexes are empty
    if indexes is None or len(indexes) == 0:
        # If no indexes are provided, return an empty list
        return []

    # Get all indexes
    all_indexes_names = set(get_all_indexes_raw())

    filtered_indexes = []
    # Filter the indexes based on the allowed indexes
    for idx_permission in indexes:
        if idx_permission.index_name in all_indexes_names:
            filtered_indexes.append(idx_permission)

    return filtered_indexes


def create_user_permission(user_id: int, index_permission: IndexPermission) -> UserPermission:
    """
    Convert a Pydantic IndexPermission model to a SQLAlchemy UserPermission ORM object.
    """
    return UserPermission(
        user_id=user_id,
        index_name=index_permission.index_name,
        read_permission=index_permission.read,
        write_permission=index_permission.write,
        delete_permission=index_permission.delete,
        effective_date=index_permission.effective_date,
        expiration_date=index_permission.expiration_date,
    )


def create_and_filter_user_permissions(user_id: int, index_permissions: List[IndexPermission]) -> List[UserPermission]:
    """
    Convert a list of Pydantic IndexPermission models to a list of SQLAlchemy UserPermission ORM objects.
    """
    # Filter the indexes based on the allowed indexes
    filtered_indexes = filter_index_permissions(index_permissions)
    
    # Convert the filtered indexes to UserPermission ORM objects
    user_permissions = [create_user_permission(user_id, index_permission) for index_permission in filtered_indexes]
    
    return user_permissions


def create_role_permission(role_id: int, index_permission: IndexPermission) -> RolePermission:
    """
    Convert a Pydantic IndexPermission model to a SQLAlchemy UserPermission ORM object.
    """
    return RolePermission(
        role_id=role_id,
        index_name=index_permission.index_name,
        read_permission=index_permission.read,
        write_permission=index_permission.write,
        delete_permission=index_permission.delete,
        effective_date=index_permission.effective_date,
        expiration_date=index_permission.expiration_date,
    )


def create_and_filter_role_permissions(role_id: int, index_permissions: List[IndexPermission]) -> List[RolePermission]:
    """
    Convert a list of Pydantic IndexPermission models to a list of SQLAlchemy UserPermission ORM objects.
    """
    # Filter the indexes based on the allowed indexes
    filtered_indexes = filter_index_permissions(index_permissions)
    
    # Convert the filtered indexes to UserPermission ORM objects
    role_permissions = [create_role_permission(role_id, index_permission) for index_permission in filtered_indexes]
    
    return role_permissions


def create_user(user: UserCreate, db: Session) -> User|dict:
    # Check if the user already exists
    if get_user_by_username(user.username, db):
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "User already exists - username."}

    if get_user_by_email(user.email, db):
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "User already exists - email."}

    # Check if the roles exist
    roles = db.query(Role).filter(Role.id.in_(user.role_ids)).all()
    if len(roles) != len(user.role_ids):
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "Some roles do not exist."}

    hashed_password = hash_password(user.password)

    db_user = User(username=user.username, hashed_password=hashed_password, email=user.email)

    # Add roles to the user
    db_user.roles = roles
    # Add permissions to the user
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    if user.permissions is not None:
        permissions = create_and_filter_user_permissions(db_user.id, user.permissions)
        db_user.permissions = permissions
        db.commit()
        db.refresh(db_user)

    return db_user


def get_all_users(db: Session) -> List[User]:
    return db.query(User).all()


def get_all_roles(db: Session) -> List[Role]:
    return db.query(Role).all()


def get_user_by_username(username: str, db: Session) -> User|None:
    """
    Retrieve a user by its username.
    """
    return db.query(User).filter(User.username == username).first()


def get_user_by_email(email: str, db: Session) -> User|None:
    """
    Retrieve a user by its username.
    """
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(user_id: int, db: Session) -> User|None:
    """
    Retrieve a user by its username.
    """
    return db.query(User).filter(User.id == user_id).first()


def get_role_by_name(role_name: str, db: Session) -> Role|None:
    """
    Retrieve a role by its name.
    """
    return db.query(Role).filter(Role.name == role_name).first()


def create_role(role: RoleCreate, db: Session) -> Role|dict:
    """
    Create a new role.
    """
    # Check if the role already exists
    db_role = get_role_by_name(role.name, db)
    if db_role:
        return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "Role already exists."}
    # Check if the parent role exists
    if role.parent_id is not None:
        parent_role = db.query(Role).filter(Role.id == role.parent_id).first()
        if not parent_role:
            return {"status_code": status.HTTP_400_BAD_REQUEST, "detail": "Parent role does not exist."}
    # Create a new role
    db_role = Role(name=role.name,description=role.description, parent_id=role.parent_id)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)

    if role.permissions is not None:
        permissions = create_and_filter_role_permissions(db_role.id, role.permissions)
        db_role.permissions = permissions
        db.commit()
        db.refresh(db_role)

    return db_role


def role_has_index_permission_defined(role: Role, index: str) -> bool:
    """
    Check if the role has access to the index.
    """
    if role.permissions is None or len(role.permissions) == 0:
        return False
    for permission in role.permissions:
        if permission.index_name == index:
            return True
    return False


def user_has_index_permission_defined(user: User, index: str) -> bool:
    """
    Check if the user has any type of permission to a given index.
    """
    if user.permissions is None or len(user.permissions) == 0:
        return False
    for permission in user.permissions:
        if permission.index_name == index:
            return True
    return False


def create_base_data(db: Session) -> User:
    """
    Create the default roles and users if they don't exist.
    """
    # Check if the admin role exists
    admin_role = get_role_by_name(ADMIN_ROLE_NAME, db)
    if not admin_role:
        # Create the admin role if it doesn't exist
        logger.debug(f"Creating admin role: {ADMIN_ROLE_NAME}")
        admin_role = create_role(RoleCreate(name=ADMIN_ROLE_NAME), db)

    # Check if the default user exists
    default_user = get_user_by_username(ADMIN_USER_USERNAME, db)
    if not default_user:
        logger.debug(f"Creating default admin user: {ADMIN_USER_USERNAME}")
        default_user = create_user(UserCreate(username=ADMIN_USER_USERNAME, password=ADMIN_USER_PASSWORD, email=ADMIN_USER_EMAIL, role_ids=[admin_role.id]), db)
    return default_user


def get_auth_token(request: Request, access_token: str = Cookie(None)):
    """
    Try to get the JWT token from the Authorization header (manually) or from cookies.
    """
    logger.debug(f"Request headers: {request.headers}")
    # Try to get the token from the Authorization header manually
    auth_header = request.headers.get("Authorization")
    if auth_header:
        scheme, token = get_authorization_scheme_param(auth_header)
        if scheme.lower() == "bearer":
            logger.debug(f"Token from Authorization header: {token}")
            return token

    # If token is not in the Authorization header, try to get it from cookies
    if access_token:
        logger.debug(f"Token from cookies: {access_token}")
        return access_token

    # If no token is found, raise an HTTP exception or handle it as needed
    logger.error("No token found in Authorization header or cookies.")
    return None


def get_user_from_token(db: Session, token: str) -> User|None:
    """
    Get the user from the JWT token.
    """
    try:
        payload = verify_token(token)
        if payload is None:
            return None
        user_id = payload.get("sub")
        if user_id is None:
            return None
        user = get_user_by_id(user_id, db)
        return user
    except jwt.PyJWTError:
        logger.exception("JWT error")
        return None


def _get_current_user(db: Session, token: str, headers: dict) -> User:
    """
    Get the current user from the JWT token.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers=headers,
    )

    try:
        user = get_user_from_token(db, token)
        if user is None:
            logger.error("User not found")
            raise credentials_exception
        return user
    except jwt.PyJWTError:
        logger.exception("JWT error")
        raise credentials_exception



def get_current_user_oauth(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """
    Get the current user from the JWT token from OAuth2.
    """
    return _get_current_user(db, token, {"WWW-Authenticate": "Bearer", "location": "/login"})


def get_current_user_cookie(db: Session = Depends(get_db), token: str = Depends(get_auth_token)) -> User:
    """
    Get the current user from the JWT token from cookie.
    """
    return _get_current_user(db, token, {"WWW-Authenticate": "Cookie", "location": "/login"})


def get_current_user_admin_oauth(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """
    Get the current user and check if they have admin role.
    """
    user = get_current_user_oauth(db, token)
    if not has_admin_role(user):
        logger.error(f"User does not have admin role. User: {user.username}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have the necessary admin permissions.")
    return user


def get_current_user_admin_cookie(db: Session = Depends(get_db), token: str = Depends(get_auth_token)) -> User:
    """
    Get the current user and check if they have admin role.
    """
    user = get_current_user_cookie(db, token)
    if not has_admin_role(user):
        logger.error(f"User does not have admin role. User: {user.username}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have the necessary admin permissions.")
    return user


def get_meta_indexes_permissions() -> Dict[str, IndexPermission]:
    """
    Get the meta indexes permissions.
    """
    # Get the meta indexes permissions
    meta_indexes = get_meta_indexes()
    meta_permissions = {}
    for index in meta_indexes:
        meta_permissions[index] = {
            "read": True,
            "write": False,
            "delete": False
        }
    return meta_permissions


def _user_has_x_access_to_index(db_user: User, index: str, access_type: str) -> bool:
    """
    Check if the user has a given X access to the index.
    :param db_user: The user object to check X permissions against.
    :param index: The index name to check.
    :return: True if the user has X read access, False otherwise.
    """
    # Check if the user is admin
    if has_admin_role(db_user):
        # Admins can read any index
        logger.debug(f"User is admin, granting access to all indexes. User: {db_user.username} Index: {index} Access Type: {access_type}")
        return True

    # Check if the index is a meta index
    meta_permissions = get_meta_indexes_permissions()
    if index in meta_permissions:
        # If the index is a meta index, check if the user has access to the original index
        if meta_permissions[index][access_type]:
            logger.debug(f"User is granted access to meta index. User: {db_user.username} Index: {index} Access Type: {access_type}")
            return True

    # Check if the user has access to the index
    if db_user.permissions is not None:
        if _check_user_access_on_idx_permission_list(db_user, index, db_user.permissions, access_type):
            return True

    # Check if the user has X access to the index in their roles
    if db_user.roles is None:
        # If roles is None, the user has no access to any index
        logger.debug(f"User has no access to the index. User: {db_user.username} Index: {index} Access Type: {access_type}")
        return False

    seen_roles = set()
    # Check if the user has access to the index in their roles
    for role in db_user.roles:
        if _check_user_access_on_idx_from_role(db_user, index, role, access_type, seen_roles):
            return True

    logger.debug(f"User has no access to the index. User: {db_user.username} Index: {index} Access Type: {access_type}")
    return False


def _check_user_access_on_idx_from_role(db_user: User, index: str, role: Role, access_type: str, seen_roles: Set[int] = {}) -> bool:
    """
    Check if the user has access to the index in their role, or if the role has a parent role with access.
    :param db_user: The user object to check permissions against.
    :param index: The index name to check.
    :param role: The role object to check permissions against.
    :param access_type: The type of access to check (read, write, delete).
    :return: True if the user has access, False otherwise.
    """
    # Avoid circular references
    if role.id in seen_roles:
        return False
    seen_roles.add(role.id)
    # Check if the user has access to the index
    if role.permissions is not None:
        if _check_user_access_on_idx_permission_list(db_user, index, role.permissions, access_type, role.name):
            return True
    if role.parent is not None:
        if _check_user_access_on_idx_from_role(db_user, index, role.parent, access_type, seen_roles):
            return True
    return False


def _check_user_access_on_idx_permission_list(db_user: User, index: str, idx_permissions: List[IndexPermission], access_type: str, role_name: str | None = None) -> bool:
    """
    Check if the user has access to the index in their permissions list.
    :param db_user: The user object to check permissions against.
    :param index: The index name to check.
    :param idx_permissions: The list of index permissions to check against.
    :param access_type: The type of access to check (read, write, delete).
    :param role_name: The name of the role to check against (if applicable).
    :return: True if the user has access, False otherwise.
    """
    # Check if the user has access to the index
    for idx_permission in idx_permissions:
        if idx_permission.index_name == index:
            # Check if the user has access to the index
            if getattr(idx_permission, access_type+"_permission", False):
                if role_name is not None:
                    logger.debug(f"User is granted access to index from role {role_name} permissions. User: {db_user.username} Index: {index} Access Type: {access_type}")
                else:
                    logger.debug(f"User is granted access to index from personal permissions. User: {db_user.username} Index: {index} Access Type: {access_type}")
                return True
    return False


def user_has_read_access_on_index(db_user: User, index: str) -> bool:
    """
    Check if the user has read access to the index.
    :param db_user: The user object to check read permissions against.
    :param index: The index name to check.
    :return: True if the user has read access, False otherwise.
    """
    return _user_has_x_access_to_index(db_user, index, "read")


def user_has_write_access_on_index(db_user: User, index: str) -> bool:
    """
    Check if the user has write access to the index.
    :param db_user: The user object to check write permissions against.
    :param index: The index name to check.
    :return: True if the user has write access, False otherwise.
    """
    return _user_has_x_access_to_index(db_user, index, "write")


def user_has_delete_access_on_index(db_user: User, index: str) -> bool:
    """
    Check if the user has delete access to the index.
    :param db_user: The user object to check delete permissions against.
    :param index: The index name to check.
    :return: True if the user has delete access, False otherwise.
    """
    return _user_has_x_access_to_index(db_user, index, "delete")


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from a request, taking into account proxy headers.
    
    Priority:
    1. X-Real-IP header
    2. First IP in X-Forwarded-For chain
    3. request.client.host (direct connection)
    """
    headers = request.headers
    
    # Check X-Real-IP first
    real_ip = headers.get("x-real-ip")
    if real_ip:
        return real_ip
        
    # Check X-Forwarded-For
    forwarded_for = headers.get("x-forwarded-for")
    if forwarded_for:
        # Get the first IP in the chain (original client)
        ips = [ip.strip() for ip in forwarded_for.split(',')]
        if ips:
            return ips[0]
    
    # Fall back to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


async def create_audit_log(
    user: Optional[User] = None,
    action: str = "",
    resource_type: str = "",
    resource_id: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None
) -> Dict[str, Any]:
    """
    Create an audit log entry for user actions with enhanced HTTP request information.
    :param db: The database session.
    :param user: The user who performed the action.
    :param action: The action performed by the user.
    :param resource_type: The type of resource affected by the action.
    :param resource_id: The ID of the resource affected by the action.
    :param success: Whether the action was successful or not.
    :param error_message: The error message if the action failed.
    :param details: Additional details about the action.
    :param request: The HTTP request object (optional).
    :return: The created Dict object.
    """
    # Extract request information if available
    url = None
    http_method = None
    user_agent = None
    ip_address = None
    forwarded_for = None
    real_ip = None
    
    if request:
        # Extract basic request info
        url = str(request.url)
        http_method = request.method
        
        # Extract headers
        headers = request.headers
        user_agent = headers.get("user-agent")
        
        # Get client IP (direct client which might be a proxy)
        ip_address = request.client.host if request.client else None
        
        # Get forwarded IPs
        forwarded_for = headers.get("x-forwarded-for")
        real_ip = get_client_ip(request)
        
    audit_entry = {
        "user_id": user.id if user else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "success": success,
        "error_message": error_message,
        "details": details,
        
        # HTTP request information
        "url": url,
        "http_method": http_method,
        "user_agent": user_agent,
        "ip_address": ip_address,
        "forwarded_for": forwarded_for,
        "real_ip": real_ip,
        
        "_time": datetime.now(timezone.utc).isoformat()  # Use UTC timezone
    }

    await get_bucket_manager().process_events(AUDIT_INDEX, [audit_entry], len(str(audit_entry)))
    return audit_entry
