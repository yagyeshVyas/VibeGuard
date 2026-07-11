create table profiles (id uuid primary key, email text);
create table orders (id uuid, user_id uuid);
alter table orders enable row level security;
