
import logging
from typing import List

from database import get_db
from fastapi import APIRouter, Request
from history import delete_user_history
from models import Role, User, UserPermission
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status
from schemas import IndexPermission, IndexesUpdate, UserCreate, UserOut, UserUpdate
import utils


logger = logging.getLogger('users')

# Initialize the APIRouter instance for user management
router = APIRouter()

MSG_USER_NOT_FOUND = "User not found"

# Route to create a new user and assign roles
@router.post("", response_model=UserOut)
async def create_user_ws(request: Request, user: UserCreate, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_admin_oauth)):
    db_user = utils.create_user(user, db)
    if isinstance(db_user, dict):
        # Log failure with request details
        await utils.create_audit_log(
            user=current_user,
            action="create_user",
            resource_type="user",
            resource_id=str(user.username),
            success=False,
            error_message=db_user["detail"],
            request=request
        )
        raise HTTPException(status_code=db_user["status_code"], detail=db_user["detail"])

    await utils.create_audit_log(
        user=current_user,
        action="create_user",
        resource_type="user",
        resource_id=str(db_user.id),
        details={"username": db_user.username, "email": db_user.email, "roles": [role.name for role in db_user.roles], "permissions": [perm.index_name for perm in db_user.permissions]},
        success=True,
        request=request
    )
    return UserOut.model_validate(db_user)


# Route to get myself
@router.get("/me", response_model=UserOut)
async def get_user(request: Request, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_oauth)):
    await utils.create_audit_log(
        user=current_user,
        action="get_user_me",
        resource_type="user",
        resource_id=str(current_user.id),
        details={"username": current_user.username, "user_id": current_user.id},
        success=True,
        request=request
    )
    return UserOut.model_validate(current_user)


# Route to get user by ID
@router.get("/{user_id}", response_model=UserOut)
async def get_user(request: Request, user_id: int, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_oauth)):

    # Allow admins to see any user, but normal users can only see their own data
    if current_user.id != user_id and not utils.has_admin_role(current_user):
        await utils.create_audit_log(
            user=current_user,
            action="get_user",
            resource_type="user",
            resource_id=str(user_id),
            success=False,
            error_message="Forbidden",
            details={"username": current_user.username, "user_id": user_id},
            request=request
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    # Fetch the user from the database
    db_user = utils.get_user_by_id(user_id, db)
    if db_user is None:
        await utils.create_audit_log(
            user=current_user,
            action="get_user",
            resource_type="user",
            resource_id=str(user_id),
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"username": current_user.username, "user_id": user_id},
            request=request
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)
    
    await utils.create_audit_log(
        user=current_user,
        action="get_user",
        resource_type="user",
        resource_id=str(db_user.id),
        success=True,
        request=request
    )
    return UserOut.model_validate(db_user)


# Route to get all users (only accessible by admin)
@router.get("", response_model=list[UserOut])
async def get_users(request: Request, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_oauth)):
    # Only admins can see all users
    if not utils.has_admin_role(current_user):
        users = [current_user]
        await utils.create_audit_log(
            user=current_user,
            action="get_users",
            resource_type="user",
            resource_id=str(current_user.id),
            success=True,
            request=request
        )
    else:
        await utils.create_audit_log(
            user=current_user,
            action="get_users",
            resource_type="user",
            resource_id="*",
            success=True,
            request=request
        )
        users = utils.get_all_users(db)

    return [UserOut.model_validate(user) for user in users]


# Route to delete a user
@router.delete("/{user_id}", response_model=UserOut)
async def delete_user(request: Request, user_id: int, db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_admin_oauth)):
    # Fetch the user from the database
    db_user = utils.get_user_by_id(user_id, db)
    if db_user is None:
        await utils.create_audit_log(
            user=current_user,
            action="delete_user",
            resource_type="user",
            resource_id=str(user_id),
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"username": current_user.username, "user_id": user_id},
            request=request
        )
        logger.debug(f"User {user_id} not found for deletion.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)
    # Check if the user is trying to delete themselves
    if db_user.id == current_user.id:
        logger.debug(f"User {current_user.username} tried to delete themselves.")
        await utils.create_audit_log(
            user=current_user,
            action="delete_user",
            resource_type="user",
            resource_id=str(user_id),
            success=False,
            error_message="Cannot delete yourself",
            details={"username": current_user.username, "user_id": user_id},
            request=request
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot delete yourself.")

    # Delete the user
    logger.debug(f"Deleting user {db_user.username} with ID {user_id}.")
    db.delete(db_user)
    db.commit()
    await utils.create_audit_log(
        user=current_user,
        action="delete_user",
        resource_type="user",
        resource_id=str(user_id),
        success=True,
        details={"username": db_user.username, "email": db_user.email, "roles": [role.name for role in db_user.roles], "permissions": [perm.index_name for perm in db_user.permissions]},
        request=request
    )

    # Delete user query history from Redis
    logger.debug(f"Deleting query history for user {db_user.username} with ID {user_id}.")
    delete_user_history(db_user.id)

    return UserOut.model_validate(db_user)


@router.put("/{user_id}/roles", response_model=UserOut)
async def assign_roles_to_user(user_id: int, role_ids: List[int], db: Session = Depends(get_db), current_user: User = Depends(utils.get_current_user_admin_oauth)):
    """
    Assign roles to a user, only accessible by admin.
    """
    db_user = utils.get_user_by_id(user_id, db)
    if db_user is None:
        await utils.create_audit_log(
            user=current_user,
            action="set_user_roles",
            resource_type="user_role",
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"user_id": user_id},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)

    roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
    if len(roles) != len(role_ids):
        await utils.create_audit_log(
            user=current_user,
            action="set_user_roles",
            resource_type="user_role",
            success=False,
            error_message="Some roles do not exist.",
            details={"user_id": user_id, "role_ids": role_ids},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Some roles do not exist.")

    db_user.roles = roles
    db.commit()
    db.refresh(db_user)
    await utils.create_audit_log(
        user=current_user,
        action="set_user_roles",
        resource_type="user_role",
        resource_id=str(user_id),
        success=True,
        details={"username": db_user.username, "email": db_user.email, "roles": [role.name for role in db_user.roles]},
    )

    return UserOut.model_validate(db_user)


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_oauth)
):
    """
    Update a user's details.
    User can only update their own details, unless they are an admin.
    Admins can update any user's details.
    """
    if user_id != current_user.id and not utils.has_admin_role(current_user):
        # Only admins can update other users
        await utils.create_audit_log(
            user=current_user,
            action="update_user",
            resource_type="user",
            resource_id=str(user_id),
            success=False,
            error_message="Only admins can update other users",
            details={"username": current_user.username, "user_id": user_id},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can update other users")

    # Retrieve the user from the database
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        await utils.create_audit_log(
            user=current_user,
            action="update_user",
            resource_type="user",
            resource_id=str(user_id),
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"username": current_user.username, "user_id": user_id},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)

    changed_data = {}
    # Update the user's details
    if user_update.password:
        # check if the password is the same as the current one
        if utils.verify_password(user_update.password, user.hashed_password):
            await utils.create_audit_log(
                user=current_user,
                action="update_user",
                resource_type="user",
                resource_id=str(user_id),
                success=False,
                error_message="New password must be different from the current one.",
                details={"username": current_user.username, "user_id": user_id},
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different from the current one.")
        # Hash the new password
        user.hashed_password = utils.hash_password(user_update.password)
        changed_data["password"] = "<UPDATED>"

    if user_update.email:
        user.email = user_update.email.lower()
        changed_data["email"] = user_update.email

    changed_data["username"] = user.username
    db.commit()
    db.refresh(user)
    await utils.create_audit_log(
        user=current_user,
        action="update_user",
        resource_type="user",
        resource_id=str(user.id),
        success=True,
        details=changed_data,
    )
    # Log the update

    return UserOut.model_validate(user)


@router.put("/{user_id}/indexes", response_model=UserOut)
async def update_user_indexes(
    user_id: int,
    indexes_update: IndexesUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_admin_oauth)
):
    """
    Update the allowed indexes for a user."
    """
    # Retrieve the role from the database
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        await utils.create_audit_log(
            user=current_user,
            action="update_user_indexes",
            resource_type="user_permission",
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"user_id": user_id},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)

    # Make sure there are no duplicates in the indexes list
    permissions = utils.create_and_filter_user_permissions(user.id, indexes_update.permissions)
    user.permissions = permissions
    db.commit()
    db.refresh(user)

    await utils.create_audit_log(
        user=current_user,
        action="update_user_indexes",
        resource_type="user_permission",
        success=True,
        details={"username": user.username, "email": user.email, "permissions": [perm.index_name for perm in user.permissions]},
    )

    return UserOut.model_validate(user)


# Add an index to a user
@router.post("/{user_id}/indexes", response_model=UserOut)
async def add_user_index(
    user_id: int,
    idx_permission: IndexPermission,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_admin_oauth)
):
    """"
    Add an index to a user, only accessible by admin.
    """
    # Retrieve the user from the database
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        await utils.create_audit_log(
            user=current_user,
            action="add_user_index",
            resource_type="user_permission",
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"user_id": user_id},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)

    # Add the index to the list if not already present
    if user.permissions is not None and len(user.permissions) > 0:
        # check if the index is already in the list
        if utils.user_has_index_permission_defined(user, idx_permission.index_name):
            logger.debug(f"Index {idx_permission.index_name} already exists in user {user.username}.")
            await utils.create_audit_log(
                user=current_user,
                action="add_user_index",
                resource_type="user_permission",
                success=False,
                error_message="Index already exists in user.",
                details={"username": user.username, "index_name": idx_permission.index_name},
            )   
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Index already exists in user.")
    logger.debug(f"Adding index {idx_permission.index_name} to user {user.username}")
    logger.debug(f"User {user.username} allowed indexes before: {user.permissions}")
    user.permissions.append(utils.create_user_permission(user.id, idx_permission))
    logger.debug(f"User {user.username} allowed indexes after: {user.permissions}")
    db.commit()
    db.refresh(user)

    await utils.create_audit_log(
        user=current_user,
        action="add_user_index",
        resource_type="user_permission",
        success=True,
        details={"username": user.username, "email": user.email, "index_name": idx_permission.index_name, "permissions": [perm.index_name for perm in user.permissions]},
    )

    return UserOut.model_validate(user)


# Remove an index from a user
@router.delete("/{user_id}/indexes/{index}", response_model=UserOut)
async def remove_user_index(
    user_id: int,
    index: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(utils.get_current_user_admin_oauth)
):
    """
    Remove an index from a user, only accessible by admin.
    """
    # Retrieve the role from the database
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        await utils.create_audit_log(
            user=current_user,
            action="delete_user_index",
            resource_type="user_permission",
            success=False,
            error_message=MSG_USER_NOT_FOUND,
            details={"user_id": user_id},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=MSG_USER_NOT_FOUND)
    
    # Retrieve the RolePermission from the database
    user_permission = db.query(UserPermission).filter(
        UserPermission.user_id == user_id,
        UserPermission.index_name == index
    ).first()
    
    if not user_permission:
        await utils.create_audit_log(
            user=current_user,
            action="delete_user_index",
            resource_type="user_permission",
            success=False,
            error_message="Index not found for this user",
            details={"username": user.username, "index_name": index},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Index not found for this user")
    
    # Delete the RolePermission
    db.delete(user_permission)
    db.commit()
    db.refresh(user)

    await utils.create_audit_log(
        user=current_user,
        action="delete_user_index",
        resource_type="user_permission",
        success=True,
        details={"username": user.username, "email": user.email, "index_name": index, "permissions": [perm.index_name for perm in user.permissions]},
    )

    return UserOut.model_validate(user)
