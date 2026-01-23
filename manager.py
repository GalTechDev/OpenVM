
import argparse
import sqlite3
import bcrypt
import sys
from docker_utils import DockerHelper

DB_PATH = 'data/db.sqlite'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def add_user(username, password, is_admin=False):
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Check if user exists
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        if c.fetchone():
            print(f"Error: User '{username}' already exists.")
            return

        # Hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Create Docker container
        try:
            container_id = DockerHelper.create_container(username)
            print(f"Container created (ID: {container_id[:12]}).")
        except Exception as e:
            print(f"Docker Error: {e}")
            return

        # Store in DB
        # Store is_admin as integer (0 or 1)
        admin_val = 1 if is_admin else 0
        c.execute('INSERT INTO users (username, password_hash, container_id, is_admin) VALUES (?, ?, ?, ?)',
                  (username, hashed.decode('utf-8'), container_id[:12], admin_val))
        conn.commit()
        print(f"User '{username}' added successfully (Admin: {is_admin}).")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def delete_user(username):
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute('SELECT container_id FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        if not result:
            print(f"Error: User '{username}' not found.")
            return

        container_id = result['container_id']

        # Remove container
        try:
            DockerHelper.remove_container(container_id)
            print(f"Container {container_id} removed.")
        except Exception as e:
            print(f"Error removing container: {e}")

        # Remove from DB
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        print(f"User '{username}' deleted.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def list_users():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT username, container_id FROM users')
    users = c.fetchall()
    conn.close()

    print(f"{'Username':<20} {'Container ID':<20}")
    print("-" * 40)
    for user in users:
        print(f"{user['username']:<20} {user['container_id']:<20}")

def change_password(username, new_password):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('SELECT rowid FROM users WHERE username = ?', (username,))
        if not c.fetchone():
            print(f"Error: User '{username}' not found.")
            return

        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        
        c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (hashed.decode('utf-8'), username))
        conn.commit()
        print(f"Password for '{username}' updated successfully.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenVM User Manager')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Add User
    parser_add = subparsers.add_parser('add_user', help='Create a new user and container')
    parser_add.add_argument('username', help='Username')
    parser_add.add_argument('password', help='Password')
    parser_add.add_argument('--admin', action='store_true', help='Grant admin privileges')

    # Delete User
    parser_del = subparsers.add_parser('delete_user', help='Delete a user and container')
    parser_del.add_argument('username', help='Username')

    # Change Password
    parser_passwd = subparsers.add_parser('change_password', help='Change user password')
    parser_passwd.add_argument('username', help='Username')
    parser_passwd.add_argument('password', help='New Password')

    # List Users
    parser_list = subparsers.add_parser('list_users', help='List all users')

    args = parser.parse_args()

    if args.command == 'add_user':
        add_user(args.username, args.password, args.admin)
    elif args.command == 'delete_user':
        delete_user(args.username)
    elif args.command == 'list_users':
        list_users()
    elif args.command == 'change_password':
        change_password(args.username, args.password)


