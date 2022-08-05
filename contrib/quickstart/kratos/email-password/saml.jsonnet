local claims = {
  email_verified: false
} + std.extVar('claims');

{
  identity: {
    traits: {
      email: claims.email,
      [if "name" in claims then "name" else null]: claims.name,
      [if "last_name" in claims then "last_name" else null]: claims.last_name,
      [if "roles" in claims then "roles" else null]: claims.roles,
    },
  },
}
