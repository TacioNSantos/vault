from enum import Enum


class Permission(str, Enum):
    Create = "create"
    Read = "read"
    Update = "update"
    Delete = "delete"


SECRET_PERMISSIONS = frozenset({Permission.Read, Permission.Update, Permission.Delete})
