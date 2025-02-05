from pydantic import BaseModel
from typing import Literal

class Hash(BaseModel):
    value: str | None = None
    type: Literal['asrep', 'tgs'] = []
    spn: str | None = None

class User(BaseModel):
    username: str | None = None
    krb_hash: list[Hash] = []
    nthash: str | None = None
    aes256: str | None = None
    password: str | None = None

class Computer(BaseModel):
    name: str | None = None
    dns_name: str | None = None
    ip_address: str | None = None
    dc: bool = False

class Domain(BaseModel):
    name: str | None = None
    sid: str | None = None
    dc: list[str] = []
    domain_admins: list[str] = []
    domain_computers: list[Computer] = []