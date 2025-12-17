from enum import Enum

class ApiCode(Enum):
    SUCCESS = (1, "成功")
    SYSTEM_ERROR = (0, "操作失败")
    NOT_FOUND = (404, "未找到该资源")

    def __init__(self, code, msg):
        self.code = code
        self.msg = msg

    @property
    def get_code(self):
        return self.code

    @property
    def get_msg(self):
        return self.msg