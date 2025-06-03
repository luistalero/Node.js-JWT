const roles = new Map()

/**
 * Assign a role to a user.
 * @param {string} userId - The ID of the user.
 * @param {string} role - The role to assign.
 */
function assignRole (userId, role) {
  if (!userId || !role) {
    throw new Error('User ID and role are required.')
  }
  roles.set(userId, role)
}

/**
 * Get the role of a user.
 * @param {string} userId - The ID of the user.
 * @returns {string|null} - The role of the user, or null if no role is assigned.
 */
function getRole (userId) {
  return roles.get(userId) || null
}

/**
 * Remove the role of a user.
 * @param {string} userId - The ID of the user.
 */
function removeRole (userId) {
  roles.delete(userId)
}

/**
 * List all roles assigned to users.
 * @returns {Array} - An array of objects containing userId and role.
 */
function listRoles () {
  return Array.from(roles.entries()).map(([userId, role]) => ({ userId, role }))
}

export default {
  assignRole,
  getRole,
  removeRole,
  listRoles
}
