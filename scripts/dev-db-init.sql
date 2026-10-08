-- The two roles authkittest runs as: authkit_owner owns every table the
-- harness creates, authkit_app is a non-owner with DML grants only. Neither
-- can bypass RLS (spec §12).
CREATE ROLE authkit_owner LOGIN PASSWORD 'authkit_owner' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE authkit_app LOGIN PASSWORD 'authkit_app' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
