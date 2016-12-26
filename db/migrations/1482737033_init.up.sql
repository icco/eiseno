CREATE TABLE IF NOT EXISTS users (id serial, email text);
CREATE TABLE IF NOT EXISTS sites (id serial, domain text, user_id bigint, ssl boolean, dns boolean);
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS credentials (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), secret_enc text, user_id bigint);
