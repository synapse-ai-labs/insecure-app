import sqlite3
from fastapi import APIRouter, Depends, status
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.security.password import get_password_hash
from app.models import User
from app.schemas.requests import UserUpdatePasswordRequest
from app.schemas.responses import UserResponse

router = APIRouter()

# Initialize the database
def init_db():
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)''')
    cursor.execute('''INSERT INTO users (name, age) VALUES ('Alice', 30)''')
    cursor.execute('''INSERT INTO users (name, age) VALUES ('Bob', 24)''')
    conn.commit()
    conn.close()


@router.get("/me", response_model=UserResponse, description="Get current user")
async def read_current_user(
    current_user: User = Depends(deps.get_current_user),
) -> User:
    return current_user


@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    description="Delete current user",
)
async def delete_current_user(
    current_user: User = Depends(deps.get_current_user),
    session: AsyncSession = Depends(deps.get_session),
) -> None:
    await session.execute(delete(User).where(User.user_id == current_user.user_id))
    await session.commit()


@router.post(
    "/reset-password",
    status_code=status.HTTP_204_NO_CONTENT,
    description="Update current user password",
)
async def reset_current_user_password(
    user_update_password: UserUpdatePasswordRequest,
    session: AsyncSession = Depends(deps.get_session),
    current_user: User = Depends(deps.get_current_user),
) -> None:
    current_user.hashed_password = get_password_hash(user_update_password.password)
    session.add(current_user)
    await session.commit()

@router.get("/team")
async def team_users(name: str):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Directly embedding user input into the SQL query (vulnerable to SQL Injection)
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    rows = cursor.fetchall()

    conn.close()
    return {"users": rows}