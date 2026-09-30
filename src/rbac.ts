export const ROLES = ['owner', 'admin', 'member', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export type Permission =
  | 'tenant:read' | 'tenant:update'
  | 'projects:read' | 'projects:write' | 'projects:delete'
  | 'members:read' | 'members:manage'
  | 'billing:read' | 'billing:manage'
  | 'audit:read';

const viewer: Permission[] = ['tenant:read', 'projects:read', 'members:read'];
const member: Permission[] = [...viewer, 'projects:write'];
const admin: Permission[] = [
  ...member, 'projects:delete', 'members:manage', 'tenant:update', 'billing:read', 'audit:read',
];
const owner: Permission[] = [...admin, 'billing:manage'];

export const ROLE_PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  viewer: new Set(viewer),
  member: new Set(member),
  admin: new Set(admin),
  owner: new Set(owner),
};

export const can = (role: Role, permission: Permission) => ROLE_PERMISSIONS[role].has(permission);

/** Privilege-escalation guard: owners manage everyone, admins only manage members and viewers. */
export function canManageRole(actor: Role, target: Role): boolean {
  if (actor === 'owner') return true;
  if (actor === 'admin') return target === 'member' || target === 'viewer';
  return false;
}
