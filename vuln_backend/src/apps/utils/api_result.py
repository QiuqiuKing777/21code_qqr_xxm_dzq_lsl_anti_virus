from src.apps.utils.api_code import ApiCode
from dataclasses import dataclass, field
from typing import Any, TypeVar, Generic

T = TypeVar('T')

@dataclass
class ApiResult(Generic[T]):
    status: int = field(default=0)
    msg: str = field(default="")
    data: T = field(default=None)

    @classmethod
    def success(cls, data: T = None):
        return cls(status=ApiCode.SUCCESS.get_code, msg=ApiCode.SUCCESS.get_msg, data=data)

    @classmethod
    def build(cls, api_code: ApiCode, data: T = None):
        return cls(status=api_code.get_code, msg=api_code.get_msg, data=data)

    @classmethod
    def error(cls, code: int, msg: str):
        return cls(status=code, msg=msg)

    def to_dict(self):
        return {
            "status": self.status,
            "msg": self.msg,
            "data": self.data
        }