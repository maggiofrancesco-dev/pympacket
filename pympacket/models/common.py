from pydantic import BaseModel
from typing import Literal

class Hash(BaseModel):
    value: str
    type: Literal['asrep', 'tgs']

class User(BaseModel):
    username: str
    hash: Hash

class CrackedUser(User):
    password: str