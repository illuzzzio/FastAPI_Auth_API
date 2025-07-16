from fastapi import FastAPI, Depends , HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel 
from passlib.context import CryptContext
from datetime import datetime , timedelta 
from jose import JWSError, jwt 
from typing import Optional
from datetime import timezone
from typing import Annotated


SECRET_KEY = "0e41ec57034b65f3891936fb8b5b1f987d7ac0baf2910cb88cfc96c3f5020afe"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# creating a fake database 

fake_db = {
  "pranjal":{
    "username": "pranjal",
    "full_name": "pranjal malhotra",
    "email": "pranjal.malhotra2024@vitstudent.ac.in",
    "hashed_password":"dsada",
    "disabled":False
  }
}

#  refering to OAuth 2 fastpi docs for hashing password 
class Token(BaseModel):
  access_token : str
  token_type: str 

class TokenData(BaseModel):
  username: Optional[str]= None 



class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
class UserINDB(User):
  hashed_password:str 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
# for verifying password 
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# for hashing password using db and username as str 
def get_password_hash(password):
  return pwd_context.hash(password)


# trying to get the user using username 
def get_user(db, username: str):
  if username in db:
    user_dict = db[username]
    return UserINDB(**user_dict)
  

  # Authenticating fof user using the verify_ password function 
def authenticate_user(fake_db, username: str, password: str):
  user = get_user(fake_db, username)
  if not user:
    return False 
  if not verify_password(password, user.hashed_password):
    return False 
  return user 


# defining time for creating access token for the user 
def create_access_token(data: dict, expires_delta: timedelta| None = None ):
  To_Encode = data.copy()
  if expires_delta:
    expire = datetime.now(timezone.utc)+ expires_delta
  else:
    expire = datetime.now(timezone.utc)+ timedelta(minutes= 15)
  To_Encode.update({"exp":expire})
  encoded_jwt = jwt.encode(To_Encode, SECRET_KEY, algorithm = ALGORITHM)
  return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]): # line number 49
  credentials_exception = HTTPException(
    status_code = status.HTTP_401_UNAUTHORIZED,
    DETAIL = "Error to validate the credentials",
    headers = {"WWW-Authenticate": "Bearer"},
  )
  try:
    payload = jwt.decode(token, SECRET_KEY, algorithm =[ALGORITHM])
    username = payload.get("sub")
    if username is None :
      raise credentials_exception
    token_data = TokenData(username= username)
  except JWSError:
    raise credentials_exception
  user = get_user(fake_db, username= token.data.username)
  if user is None:
    raise credentials_exception
  return user  
  


async def get_current_active_user(
  current_user: Annotated[User, Depends(get_current_user)],
):
  if current_user.disabled:
      raise HTTPException(status_code=400, detail="Inactive user")
  return current_user



@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]

