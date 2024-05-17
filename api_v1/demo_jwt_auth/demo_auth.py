from jwt import InvalidTokenError
from fastapi import APIRouter, Depends, Form, HTTPException, status
from users.schemas import UserSchema
from pydantic import BaseModel
from auth import utils as auth_utils
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


http_bearer = HTTPBearer()

router = APIRouter(prefix="/jwt", tags=["JWT"])


class TokenInfo(BaseModel):
    access_token: str
    token_type: str


john = UserSchema(
    username="john",
    password=auth_utils.hash_password("qwerty"),
    email="john@example.com",
)


sam = UserSchema(
    username="sam",
    password=auth_utils.hash_password("secret"),
    email="sam@example.com",

)


users_db: dict = {
    john.username: john,
    sam.username: sam,
}


def validate_auth_user(username: str = Form(), password: str = Form()):
    unauthed_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    if not (user := users_db.get(username)):
        raise unauthed_exception
    if auth_utils.validate_password(password=password, hashed_password=user.password):
        return user
    raise unauthed_exception


# Помощник получения словаря payload с данными о пользователе
def get_current_token_payload(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)) -> UserSchema:
    token = credentials.credentials
    try:
        payload = auth_utils.decode_jwt(token=token)
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token error {e}")
    return payload


# Получение информации о пользователе по токену - помощник для VIEW
def get_current_auth_user(payload: dict = Depends(get_current_token_payload)) -> UserSchema:
    username: str = payload.get("sub")
    if not(user := users_db.get(username)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token invalid (user not found)")
    return user

# Получение АКТИВНОГО пользователя
def get_current_active_auth_user(user: UserSchema = Depends(get_current_auth_user)):
    if user.active:
        return user
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user inactive")



@router.post("/login", response_model=TokenInfo)
def auth_user_issue_jwt(user: UserSchema = Depends(validate_auth_user)):
    jwt_payload = {
        "sub": user.username,
        "username": user.username,
        "email": user.email
    }
    token = auth_utils.encode_jwt(jwt_payload)
    return TokenInfo(
        access_token=token,
        token_type="Bearer"
    )


# Получение информации о пользователе по токену - View
@router.get("/users/me")
def auth_user_check_self_info(user: UserSchema = Depends(get_current_active_auth_user)):
    return {
        "username": user.username,
        "email": user.email,
    }