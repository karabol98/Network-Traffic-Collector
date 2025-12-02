from datetime import datetime, timezone
import re
from pydantic import BaseModel, ConfigDict, model_validator
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from typing import Optional
from pydantic import BaseModel
from typing import List

# Schema for index permissions to be used in Role and User permission schemas
class IndexPermission(BaseModel):
    index_name: str
    # Permissions for the index with default values
    read: bool = True
    write: bool = False
    delete: bool = False
    # This is the date when the permission becomes effective
    effective_date: datetime = datetime.now(timezone.utc)
    # This is the date when the permission expires
    expiration_date: Optional[datetime] | None = None

    model_config = ConfigDict(from_attributes=True)  


# Role schema for creating a new role
class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None  # Description of the role
    parent_id: Optional[int] = None  # ID of the parent role
    permissions: Optional[List[IndexPermission]] = None # List of indexes associated with the role

    @model_validator(mode="before")
    def validate_name(cls, values):
        name = values.get("name")
        if name and not re.match(r"^\w+$", name):
            raise ValueError("Name can only contain letters, numbers and underscores.")
        
        return values


# Role schema to be used in UserOut
class RoleOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None  # Description of the role
    parent_id: Optional[int] = None  # ID of the parent role
    permissions: Optional[List[IndexPermission]] = None  # List of indexes associated with the role
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)  

# User schema for login
class UserLogin(BaseModel):
    username: str
    password: str


# User schema for creating a new user
class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    role_ids: List[int] # List of role IDs to assign to the user
    permissions: Optional[List[IndexPermission]] = None # List of indexes associated with the user

    @model_validator(mode="before")
    def validate_username(cls, values):
        username = values.get("username")
        if not username:
            raise ValueError("Username is required.")
        elif len(username) < 3 or len(username) > 16:
            raise ValueError("Username must be between 3 and 16 characters.")
        elif not re.match(r"^[a-zA-Z0-9_\.@-]+$", username):
            raise ValueError("Username can only contain letters, numbers, underscores, ats, dots, and hyphens.")
        
        return values
            
    @model_validator(mode="before")
    def validate_password(cls, values):
        password = values.get("password")
        if password:
            # Check password length
            if len(password) < 10:
                raise ValueError("Password must be at least 10 characters.")
        else:
            raise ValueError("Password is required.")
        
        return values
    
    @model_validator(mode="before")
    def validate_email(cls, values):
        email = values.get("email")
        if email and not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            raise ValueError("Invalid email format.")
        
        return values
    
    @model_validator(mode="before")
    def validate_role_ids(cls, values):
        role_ids = values.get("role_ids")
        if not role_ids:
            raise ValueError("At least one role ID is required.")
        
        return values

class UserUpdate(BaseModel):
    password: Optional[str] = None
    email: Optional[str] = None

    @model_validator(mode="before")
    def validate_password(cls, values):
        password = values.get("password")
        if password:
            # Check password length
            if len(password) < 10:
                raise ValueError("Password must be at least 10 characters.")
        
        return values

    @model_validator(mode="before")
    def validate_email(cls, values):
        email = values.get("email")
        if email and not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            raise ValueError("Invalid email format.")
        
        return values
    
    @model_validator(mode="before")
    def validate_password_or_email(cls, values):
        password = values.get("password")
        email = values.get("email")
        if not password and not email:
            raise ValueError("At least one of password or email must be provided.")
        
        return values


# User schema for returning user data (with roles)
class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str]
    roles: List[RoleOut]  # List of roles associated with the user
    permissions: Optional[List[IndexPermission]]  # List of indexes associated with the user
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)  

class IndexesUpdate(BaseModel):
    permissions: List[IndexPermission]  # List of new indexes

    @model_validator(mode="before")
    def validate_indexes(cls, values):
        permissions = values.get("permissions")
        if not permissions or not isinstance(permissions, list) or len(permissions) == 0:
            raise ValueError("At least one index is required.")
        
        return values
    

class SigmaRuleImportRequest(BaseModel):
    url: str
    source_type: str = "url"  

class SigmaRuleResponse(BaseModel):
    id: int
    sigmarule_id: str

class SigmaRuleIndexMapRequest(BaseModel):
    sigma_rule_id: int
    index_name: str
    sql_query: Optional[str] = None
    schedule: Optional[str] = None  # optional cron expression
    enabled: Optional[bool] = True

class SigmaRuleIndexResponse(BaseModel):
    id: int
    sigma_rule_id: int
    index_name: str
    sql_query: Optional[str]
    schedule: Optional[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class FieldMappingItem(BaseModel):
    sigma_field: str
    index_field: str

class FieldMappingRequest(BaseModel):
    sigma_rule_index_id: int
    mappings: List[FieldMappingItem]

class FieldMappingRequest(BaseModel):
    SigmaRule_index_id: int
    SigmaRule_FieldName: str
    Index_FieldName: str

class FieldMappingResponse(BaseModel):
    id: int
    SigmaRule_index_id: int
    SigmaRule_FieldName: str
    Index_FieldName: str
    created_at: datetime

class MySchema(BaseModel):
    ...
    class Config:
        from_attributes = True

class RuleExecutionLogCreate(BaseModel):
    rule_id: int
    validated_index: str
    result: str

class RuleExecutionLogRead(RuleExecutionLogCreate):
    id: int
    executed_at: datetime

    class Config:
        orm_mode = True
