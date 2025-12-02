#!/usr/bin/env python3
import argparse
import sys
from database import get_db
from user_management.models import User
import traceback
from utils import update_password  # Import the update function

def main():
    parser = argparse.ArgumentParser(description='Set a user password using hash_password from utils.py')
    parser.add_argument('username', help='Username of the account')
    parser.add_argument('password', help='Password to be hashed and set')
    
    args = parser.parse_args()

    db = next(get_db())
    
    try:
        # Update the user's password in the database
        update_result = update_password(args.username, args.password, db)
        
        if update_result and isinstance(update_result, User):
            user = update_result
            print(f"Username: {user.username}")
            print("Password updated successfully in the database")
        else:
            print(f"Failed to update password for user {args.username}: {update_result.detail if update_result else None}", file=sys.stderr)
            sys.exit(1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()