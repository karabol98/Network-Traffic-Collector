
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from models import User
from sqlalchemy.orm import Session

from schemas import UserLogin
from database import get_db
import utils

logger = logging.getLogger('auth')

router = APIRouter()

# Route to log in and get a JWT token
@router.post("/login")
async def login(request: Request, user_login: UserLogin, db: Session = Depends(get_db)):

    try:
        db_user = utils.get_user_by_username(user_login.username, db)
        if db_user is None or not utils.verify_password(user_login.password, db_user.hashed_password):
            logger.debug(f"Login failed for user {user_login.username}. Invalid credentials.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        logger.debug(f"User {user_login.username} logged in successfully.")
        # Log successful login
        await utils.create_audit_log(
            user=db_user,
            action="login",
            resource_type="authentication",
            success=True,
            request=request
        )

        # Generate JWT token
        access_token = utils.create_user_access_token(db_user)

        logger.debug(f"Generated JWT token for user {user_login.username}: {access_token}")

        response = JSONResponse(content={"message": "Login successful", "access_token": access_token, "token_type": "bearer"})
        # Set the token in a cookie (e.g., HTTP-only cookie for security)
        response.set_cookie(
            key="access_token",  # Cookie name
            value=access_token,  # The JWT token
            httponly=True,  # Make cookie HTTP-only (can't be accessed via JS)
            max_age=utils.JWT_ACCESS_TOKEN_EXPIRE_SECONDS,  # Set expiration
            secure=utils.SECURE_COOKIE,  # Only send the cookie over HTTPS in production
            samesite="Strict"  # Cookie will only be sent to same-site requests
        )

        return response
    except HTTPException as e:
        # Log failure with request details
        await utils.create_audit_log(
            user=None,
            action="login",
            resource_type="authentication",
            success=False,
            error_message=str(e.detail),
            details={"username_attempt": user_login.username},
            request=request
        )
        raise e
    except Exception as e:
        logger.error(f"An error occurred during login: {str(e)}")
        # Log failure with request details
        await utils.create_audit_log(
            user=None,
            action="login",
            resource_type="authentication",
            success=False,
            error_message=str(e),
            details={"username_attempt": user_login.username},
            request=request
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error: {str(e)}")


@router.post("/logout")
async def logout(request: Request, current_user: User = Depends(utils.get_current_user_oauth), db: Session = Depends(get_db)):
    response = JSONResponse(content={"message": "Logout successful"})
    # Clear the cookie by setting its max_age to 0
    response.delete_cookie("access_token")
    # Log failure with request details
    await utils.create_audit_log(
        user=current_user,
        action="logout",
        resource_type="authentication",
        success=True,
        request=request
    )
    return response