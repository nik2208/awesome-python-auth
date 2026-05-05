"""Role-Based Access Control (RBAC) store for awesome-python-auth.

Provides the abstract :class:`RolesPermissionsStore` interface and a
:class:`InMemoryRolesPermissionsStore` implementation suitable for tests and
small single-process deployments.

Usage::

    from awesome_python_auth import RolesPermissionsStore, InMemoryRolesPermissionsStore

    store = InMemoryRolesPermissionsStore()
    await store.create_role("admin", permissions=["users:read", "users:write"])
    await store.add_role_to_user("user-123", "admin")
    roles = await store.get_roles_for_user("user-123")  # ["admin"]
    perms = await store.get_permissions_for_user("user-123")  # ["users:read", "users:write"]
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class RolesPermissionsStore(ABC):
    """Abstract store for role-based access control (RBAC).

    Implement this interface and pass an instance to :class:`~awesome_python_auth.config.AuthConfig`
    as ``roles_permissions_store``.  The auth router will then automatically populate
    ``roles`` and ``permissions`` in every JWT access token at login and refresh time.

    All tenant-aware methods accept an optional ``tenant_id`` parameter so the same
    interface works for both single-tenant and multi-tenant applications.
    """

    # ------------------------------------------------------------------
    # User ↔ Role assignments
    # ------------------------------------------------------------------

    @abstractmethod
    async def add_role_to_user(self, user_id: str, role: str, tenant_id: str | None = None) -> None:
        """Assign *role* to the given user.

        When *tenant_id* is provided the assignment is scoped to that tenant.
        Idempotent — calling it when the assignment already exists must not raise.
        """

    @abstractmethod
    async def remove_role_from_user(self, user_id: str, role: str, tenant_id: str | None = None) -> None:
        """Remove *role* from the given user.

        When *tenant_id* is provided only the tenant-scoped assignment is removed.
        No-op when the user does not have the role.
        """

    @abstractmethod
    async def get_roles_for_user(self, user_id: str, tenant_id: str | None = None) -> list[str]:
        """Return the list of roles assigned to the given user.

        When *tenant_id* is provided only roles scoped to that tenant are returned.
        """

    # ------------------------------------------------------------------
    # Role management
    # ------------------------------------------------------------------

    @abstractmethod
    async def create_role(self, role: str, permissions: list[str] | None = None) -> None:
        """Create a new role, optionally pre-loading it with a set of permissions.

        Idempotent — calling it on an existing role must not raise.
        """

    @abstractmethod
    async def delete_role(self, role: str) -> None:
        """Delete a role and all its permission assignments.

        User ↔ role assignments for this role should also be removed.
        """

    # ------------------------------------------------------------------
    # Role ↔ Permission assignments
    # ------------------------------------------------------------------

    @abstractmethod
    async def add_permission_to_role(self, role: str, permission: str) -> None:
        """Add *permission* to *role*.

        Idempotent — adding an already-assigned permission must not raise.
        """

    @abstractmethod
    async def remove_permission_from_role(self, role: str, permission: str) -> None:
        """Remove *permission* from *role*."""

    @abstractmethod
    async def get_permissions_for_role(self, role: str) -> list[str]:
        """Return all permissions assigned to *role*."""

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @abstractmethod
    async def get_permissions_for_user(self, user_id: str, tenant_id: str | None = None) -> list[str]:
        """Return all permissions the user has, aggregated across all their roles.

        When *tenant_id* is provided only roles scoped to that tenant are considered.
        """

    @abstractmethod
    async def user_has_permission(self, user_id: str, permission: str, tenant_id: str | None = None) -> bool:
        """Check whether the user has a specific permission (across any of their roles)."""

    async def get_all_roles(self) -> list[str]:
        """Return all role names defined in the store.

        Used by the optional admin router to display the roles & permissions table.
        Override in your implementation.
        """
        return []


class InMemoryRolesPermissionsStore(RolesPermissionsStore):
    """Thread-safe in-memory RBAC store.

    Suitable for testing, examples, and single-process deployments.
    All data is lost on restart — use a database-backed implementation for production.
    """

    def __init__(self) -> None:
        # role_name -> set[permission]
        self._role_permissions: dict[str, set[str]] = {}
        # (user_id, tenant_id | None) -> set[role]
        self._user_roles: dict[tuple[str, str | None], set[str]] = {}

    # ------------------------------------------------------------------
    # User ↔ Role
    # ------------------------------------------------------------------

    async def add_role_to_user(self, user_id: str, role: str, tenant_id: str | None = None) -> None:
        key = (user_id, tenant_id)
        if key not in self._user_roles:
            self._user_roles[key] = set()
        self._user_roles[key].add(role)

    async def remove_role_from_user(self, user_id: str, role: str, tenant_id: str | None = None) -> None:
        key = (user_id, tenant_id)
        if key in self._user_roles:
            self._user_roles[key].discard(role)

    async def get_roles_for_user(self, user_id: str, tenant_id: str | None = None) -> list[str]:
        key = (user_id, tenant_id)
        return sorted(self._user_roles.get(key, set()))

    # ------------------------------------------------------------------
    # Role management
    # ------------------------------------------------------------------

    async def create_role(self, role: str, permissions: list[str] | None = None) -> None:
        if role not in self._role_permissions:
            self._role_permissions[role] = set()
        if permissions:
            self._role_permissions[role].update(permissions)

    async def delete_role(self, role: str) -> None:
        self._role_permissions.pop(role, None)
        # Remove the role from all user assignments
        for key, roles in list(self._user_roles.items()):
            roles.discard(role)

    # ------------------------------------------------------------------
    # Role ↔ Permission
    # ------------------------------------------------------------------

    async def add_permission_to_role(self, role: str, permission: str) -> None:
        if role not in self._role_permissions:
            self._role_permissions[role] = set()
        self._role_permissions[role].add(permission)

    async def remove_permission_from_role(self, role: str, permission: str) -> None:
        if role in self._role_permissions:
            self._role_permissions[role].discard(permission)

    async def get_permissions_for_role(self, role: str) -> list[str]:
        return sorted(self._role_permissions.get(role, set()))

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    async def get_permissions_for_user(self, user_id: str, tenant_id: str | None = None) -> list[str]:
        roles = await self.get_roles_for_user(user_id, tenant_id)
        perms: set[str] = set()
        for role in roles:
            perms.update(self._role_permissions.get(role, set()))
        return sorted(perms)

    async def user_has_permission(self, user_id: str, permission: str, tenant_id: str | None = None) -> bool:
        perms = await self.get_permissions_for_user(user_id, tenant_id)
        return permission in perms

    async def get_all_roles(self) -> list[str]:
        return sorted(self._role_permissions.keys())
