from pydantic import BaseModel
from typing import Literal

class Hash(BaseModel):
    value: str = None
    type: Literal['asrep', 'tgs'] = []
    spn: str = None

class User(BaseModel):
    username: str = None
    krb_hash: list[Hash] = []
    nthash: str = None
    aes256: str = None
    password: str = None

class Computer(BaseModel):
    name: str = None
    dns_name: str = None
    ip_address: str = None
    dc: bool = False

class Domain(BaseModel):
    name: str = None
    sid: str = None
    dc: list[str] = []
    domain_admins: list[str] = []
    domain_computers: list[Computer] = []