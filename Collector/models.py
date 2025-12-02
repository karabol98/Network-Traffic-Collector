from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, UniqueConstraint, Text
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone
from database import Base 

Base = declarative_base()

class BasePermission(Base):
    __abstract__ = True

    index_name = Column(String, primary_key=True)

    read_permission = Column(Boolean, default=True)
    write_permission = Column(Boolean, default=False)
    delete_permission = Column(Boolean, default=False)

    effective_date = Column(DateTime, default=datetime.now(timezone.utc), nullable=False)
    expiration_date = Column(DateTime, default=None, nullable=True)

class RolePermission(BasePermission):
    __tablename__ = 'role_permissions'

    role_id = Column(Integer, ForeignKey('roles.id'), primary_key=True)
    # Define a relationship to the Role model
    role = relationship('Role', back_populates='permissions')

class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    # Parent role (self-referential foreign key)
    parent_id = Column(Integer, ForeignKey('roles.id'), nullable=True)

    # Relationships
    parent = relationship('Role', remote_side=[id], backref='children')

    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    # Define a relationship to the users
    users = relationship("User", secondary="user_roles", back_populates="roles")
    # Define a relationship to the permissions
    permissions = relationship('RolePermission', back_populates='role', cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Define a many-to-many relationship with the Role model
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    # Define a one-to-many relationship with the UserPermission model
    permissions = relationship('UserPermission', back_populates='user', cascade="all, delete-orphan")


class UserPermission(BasePermission):
    __tablename__ = 'user_permissions'

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    # Define a relationship to the Role model
    user = relationship('User', back_populates='permissions')


class UserRoles(Base):
    __tablename__ = "user_roles"
    
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)


# -------- Sigma Rule Models --------
class SigmaRuleSource(Base):
    __tablename__ = "sigma_rule_source"
    id = Column(Integer, primary_key=True)
    url = Column(String, nullable=False)
    type = Column(String, nullable=True)  # π.χ. github, local
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc))


class SigmaRule(Base):
    __tablename__ = "sigma_rules"
    id = Column(Integer, primary_key=True)
    sigmarule_id = Column(String)
    sigma_rule_content = Column(Text)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc))
    executions = relationship("RuleExecutionLog", back_populates="rule")


class SigmaRuleIndex(Base):
    __tablename__ = "sigmarules_indexes"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    SigmaRule_id = Column(Integer, ForeignKey("sigma_rules.id"))
    IndexName = Column(String)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc))
    SQL_Query = Column(Text)
    schedule = Column(String)  # π.χ. cron expression
    enabled = Column(Boolean, default=True)
    last_executed_at = Column(DateTime, nullable=True)
    next_execution_at = Column(DateTime, nullable=True)

    sigma_rule = relationship("SigmaRule")


class SigmaRuleFieldMapping(Base):
    __tablename__ = "sigmarules_indexes_fields_map"
    id = Column(Integer, primary_key=True)
    SigmaRule_index_id = Column(Integer, ForeignKey("sigmarules_indexes.id"))
    SigmaRule_FieldName = Column(String)
    Index_FieldName = Column(String)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))


class SigmaRuleExecution(Base):
    __tablename__ = "sigma_rule_executions"
    id = Column(Integer, primary_key=True)
    SigmaRule_index_id = Column(Integer, ForeignKey("sigmarules_indexes.id"))
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    num_rows = Column(Integer)


class SigmaRuleExecutionResult(Base):
    __tablename__ = "sigma_rule_execution_results"
    id = Column(Integer, primary_key=True)
    execution_id = Column(Integer, ForeignKey("sigma_rule_executions.id"))
    result_data = Column(Text)

class Index(Base):
    __tablename__ = "indexes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    rule_associations = relationship("RuleIndexAssociation", back_populates="index")


class RuleIndexAssociation(Base):
    __tablename__ = 'rule_index_associations'

    id = Column(Integer, primary_key=True)
    rule_id = Column(ForeignKey("sigma_rules.id"), nullable=False)
    active = Column(Boolean, default=True)
    schedule = Column(String, nullable=True)  # e.g. "*/10 * * * * *"
    index_id = Column(Integer, ForeignKey("indexes.id"))
    index = relationship("Index", back_populates="rule_associations")

class RuleExecutionLog(Base):
    __tablename__ = "rule_execution_logs"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("sigma_rules.id"), nullable=False)
    scheduled_for = Column(DateTime, nullable=False)
    validated_index = Column(String, nullable=False)
    executed_at = Column(DateTime, default=datetime.utcnow)
    result = Column(Text)

    rule = relationship("SigmaRule", back_populates="executions")