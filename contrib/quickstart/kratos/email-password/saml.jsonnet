local claims = {
  email_verified: false
} + std.extVar('claims');

{
  identity: {
    traits: {
      [if "email" in claims && claims.email_verified then "email" else null]: claims.email,
      [if "name" in claims then "name" else null]: claims.name,
      [if "last_name" in claims then "last_name" else null]: claims.last_name,
      [if "nickname" in claims then "nickname" else null]: claims.nickname,
      [if "picture" in claims then "picture" else null]: claims.picture,
      [if "phone_number" in claims then "phone_number" else null]: claims.phone_number,
      [if "gender" in claims then "gender" else null]: claims.gender,
      [if "birthdate" in claims then "birthdate" else null]: claims.birthdate,
      [if "roles" in claims then "roles" else null]: claims.roles,
    },
  },
}
