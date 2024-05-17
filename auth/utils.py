import jwt
import bcrypt
from datetime import datetime, timedelta
from core.config import settings


def encode_jwt(payload: dict,
               private_key: str = settings.auth_jwt.private_key_path.read_text(),
               algorithm: str = settings.auth_jwt.algorithm
               ):
    # Копируем словарь Payload
    to_encode = payload.copy()
    # Получение времени выпуска токена
    iat = datetime.utcnow()
    # Получения времени жизни токена
    expire_minutes: int = settings.auth_jwt.access_token_expire_minutes
    expire = datetime.utcnow() + timedelta(minutes=expire_minutes)
    # Добавляем в него дату истечения JWT токена "exp" и время выпуска "iat"
    to_encode.update(exp=expire, iat=iat)
    encoded = jwt.encode(to_encode, private_key, algorithm=algorithm)
    return encoded


def decode_jwt(token: str,
               public_key: str = settings.auth_jwt.public_key_path.read_text(),
               algorithm: str = settings.auth_jwt.algorithm
               ):
    decoded = jwt.decode(token, public_key, algorithms=[algorithm])
    return decoded


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    pwd_bytes: bytes = password.encode()
    return bcrypt.hashpw(pwd_bytes, salt)


def validate_password(password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(
        password=password.encode(),
        hashed_password=hashed_password
    )
