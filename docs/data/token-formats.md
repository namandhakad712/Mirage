# Inert honeytoken formats (I14). A honeytoken must NEVER validate against a
# real service. Two guarantees:
#   1. The mrg_ namespace is issued by no real provider.
#   2. Any URL/host/address uses reserved values from reserved-hosts.txt.
# Minting is seeded (DECOY-CATALOG §4): sha256(session_key + entry_id + token_id).

format: token_alnum_24
template: mrg_live_{{24_ALNUM}}
inert-because: "No service issues mrg_live_ keys; the mrg_ namespace is reserved by this project."
example: mrg_live_9k2mf7xq4wbvt1z6n8p3rds0

format: token_bearer_32
template: mrg_bearer_{{32_ALNUM}}
inert-because: "Same namespace guarantee; visibly project-scoped to anyone who knows the format, opaque to pattern-matching credential searchers that just try shapes."
example: mrg_bearer_7f3k9q2m8xv1t4z6n5p0r3s6w9y2b5c8

format: db_password
template: mrg-pw-{{20_ALNUM}}
inert-because: "Embedded only in decoy DATABASE_URL strings pointing at reserved hosts (db.test); the password never authenticates anything real."
example: mrg-pw-4n8k2m6q9w3x7z1t5v0b

format: aws_access_key
template: AKIAMRG{{13_UPPER_ALNUM}}
inert-because: "Real AWS key ids never contain the substring MRG at position 5-7; the format is documented here as deliberately non-issuable."
example: AKIAMRGQ7XK2M9T4WZ1

format: db_url_postgres
template: postgres://deploy:{{TOKEN:db_password}}@db.test:5432/staging
inert-because: "Host db.test is RFC 2606 reserved; the port and database name are fixed decoy values."
example: postgres://deploy:mrg-pw-4n8k2m6q9w3x7z1t5v0b@db.test:5432/staging
