import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from models import RolePermission, User, Role
from database import get_db  # Importing get_db from database.py
from schemas import IndexPermission, IndexesUpdate, RoleCreate, RoleOut  # Importing the Pydantic models from schemas.py
import utils
from typing import List

MSG_USER_NOT_FOUND = "User not found"
MSG_ROLE_NOT_FOUND = "Role not found"

logger = logging.getLogger('routes')

# Initialize the APIRouter instance for user management
router = APIRouter()


# Create a new role
@router.post("", response_model=RoleOut)
async def create_role(request: Request, role: RoleCreate, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_admin_oauth)):
    """
    Create a new role, only accessible by admin.
    """
    # Create a new role
    db_role = utils.create_role(role, db)
    if isinstance(db_role, dict):
        await utils.create_audit_log(
            user=current_user,
            action="create_role",
            resource_type="role",
            success=False,
            error_message=db_role["detail"],
            request=request
        )
        raise HTTPException(status_code=db_role["status_code"], detail=db_role["detail"])

    await utils.create_audit_log(
        user=current_user,
        action="create_role",
        resource_type="role",
        resource_id=str(db_role.id),
        success=True,
        details={"name": db_role.name, "description": db_role.description},
        request=request
    )
    return RoleOut.model_validate(db_role)


# List all roles
@router.get("", response_model=list[RoleOut])
async def list_roles(request: Request, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_oauth)):
    """
    List all roles.
    """
    roles = utils.get_all_roles(db)
    if roles is None: # should never happen
        logger.debug("No roles found.")
        await utils.create_audit_log(
            user=current_user,
            action="get_roles",
            resource_type="role",
            success=False,
            error_message="Roles not found",
            request=request
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No roles found")
    # Convert the roles to the Pydantic model and return them
    await utils.create_audit_log(
        user=current_user,
        action="get_roles",
        resource_type="role",
        resource_id="*",
        success=True,
        request=request
    )
    return [RoleOut.model_validate(role) for role in roles]


# Delete a role
@router.delete("/{role_id}", response_model=RoleOut)
async def delete_role(
    role_id: int, 
    request: Request,
    db: Session = Depends(get_db), current_user
    : User = Depends(utils.get_current_user_admin_oauth)
):
    """
    Delete a role, only accessible by admin.
    """
    # Retrieve the role from the database
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        # Log failure with request details
        await utils.create_audit_log(
            user=current_user,
            action="delete_role",
            resource_type="role",
            resource_id=str(role_id),
            success=False,
            error_message=MSG_ROLE_NOT_FOUND,
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_ROLE_NOT_FOUND)
    
    # Check if the role is being used by any users
    if role.users:
        # Log failure with request details
        await utils.create_audit_log(
            user=current_user,
            action="delete_role",
            resource_type="role",
            resource_id=str(role_id),
            success=False,
            error_message="Cannot delete role with users.",
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete role with users.")
    
    # Check if the role has child roles
    if role.children:
        # Log failure with request details
        await utils.create_audit_log(
            user=current_user,
            action="delete_role",
            resource_type="role",
            resource_id=str(role_id),
            success=False,
            error_message="Cannot delete role with child roles.",
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete role with child roles.")

    # Delete the role
    db.delete(role)
    db.commit()

    # Log successful deletion with request details
    await utils.create_audit_log(
        user=current_user,
        action="delete_role",
        resource_type="role",
        resource_id=str(role_id),
        success=True,
        details={"name": role.name, "description": role.description},
        request=request  # Pass the request object
    )

    return RoleOut.model_validate(role)



# Route to update indexes for a role, only accessible by admin
@router.put("/{role_id}/indexes", response_model=RoleOut)
async def update_role_indexes(
    role_id: int,
    indexes_update: IndexesUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_admin_oauth)
):
    """
    Update the allowed indexes for a role, only accessible by admin.
    """
    # Retrieve the role from the database
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        await utils.create_audit_log(
            user=current_user,
            action="update_role_indexes",
            resource_type="role_permission",
            success=False,
            error_message=MSG_ROLE_NOT_FOUND,
            details={"role_id": role_id},
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_ROLE_NOT_FOUND)

    # Update the indexes (add or replace)
    # Make sure there are no duplicates in the indexes list
    permissions = utils.create_and_filter_role_permissions(role.id, indexes_update.permissions)
    role.permissions = permissions
    db.commit()
    # Refresh the role to get the updated permissions
    db.refresh(role)
    await utils.create_audit_log(
        user=current_user,
        action="update_role_indexes",
        resource_type="role_permission",
        success=True,
        details={"role_name": role.name, "role_description": role.description, "permissions": [perm.index_name for perm in role.permissions]},
        request=request  # Pass the request object
    )

    return RoleOut.model_validate(role)


# Add an index to a role
@router.post("/{role_id}/indexes", response_model=RoleOut)
async def add_role_index(
    role_id: int,
    idx_permission: IndexPermission,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_admin_oauth)
):
    """"
    Add an index to a role, only accessible by admin.
    """
    # Retrieve the role from the database
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        await utils.create_audit_log(
            user=current_user,
            action="add_role_index",
            resource_type="role_permission",
            success=False,
            error_message=MSG_ROLE_NOT_FOUND,
            details={"role_id": role_id},
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_ROLE_NOT_FOUND)

    # Add the index to the list if not already present
    if role.permissions is not None and len(role.permissions) > 0:
        # check if the index is already in the list
        if utils.role_has_index_permission_defined(role, idx_permission.index_name):
            logger.debug(f"Index {idx_permission.index_name} already exists in role {role.name}.")
            await utils.create_audit_log(
                user=current_user,
                action="add_role_index",
                resource_type="role_permission",
                success=False,
                error_message="Index already exists in role.",
                details={"role_name": role.name, "index_name": idx_permission.index_name},
                request=request  # Pass the request object
            )

            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Index already exists in role.")
    logger.debug(f"Adding index {idx_permission.index_name} to role {role.name}")
    logger.debug(f"Role {role.name} allowed indexes before: {role.permissions}")
    role.permissions.append(utils.create_role_permission(role.id, idx_permission))
    logger.debug(f"Role {role.name} allowed indexes after: {role.permissions}")
    db.commit()
    db.refresh(role)
    await utils.create_audit_log(
        user=current_user,
        action="add_role_index",
        resource_type="role_permission",
        success=True,
        details={"role_name": role.name, "role_description": role.description, "permissions": [perm.index_name for perm in role.permissions]},
        request=request  # Pass the request object
    )

    return RoleOut.model_validate(role)


# Remove an index from a role
@router.delete("/{role_id}/indexes/{index}", response_model=RoleOut)
async def remove_role_index(
    role_id: int,
    index: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_admin_oauth)
):
    """
    Remove an index from a role, only accessible by admin.
    """
    # Retrieve the role from the database
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        await utils.create_audit_log(
            user=current_user,
            action="delete_role_index",
            resource_type="role_permission",
            success=False,
            error_message=MSG_ROLE_NOT_FOUND,
            details={"role_id": role_id},
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_ROLE_NOT_FOUND)
    
    # Retrieve the RolePermission from the database
    role_permission = db.query(RolePermission).filter(
        RolePermission.role_id == role_id,
        RolePermission.index_name == index
    ).first()
    
    if not role_permission:
        await utils.create_audit_log(
            user=current_user,
            action="delete_role_index",
            resource_type="role_permission",
            success=False,
            error_message="Index not found for this role",
            details={"role_name": role.name, "index_name": index},
            request=request  # Pass the request object
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Index not found for this role")
    
    # Delete the RolePermission
    db.delete(role_permission)
    db.commit()
    db.refresh(role)
    await utils.create_audit_log(
        user=current_user,
        action="delete_role_index",
        resource_type="role_permission",
        success=True,
        details={"role_name": role.name, "role_description": role.description, "permissions": [perm.index_name for perm in role.permissions]},
        request=request  # Pass the request object
    )

    return RoleOut.model_validate(role)
