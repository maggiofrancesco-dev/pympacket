from typing import Annotated
from pydantic import Field
from pympacket.models.common import User

class KerberoastUser(User):
    spn: Annotated[str, Field(pattern=r'^[A-Za-z0-9]+/[A-Za-z0-9.-]+(:\d+)?$')]