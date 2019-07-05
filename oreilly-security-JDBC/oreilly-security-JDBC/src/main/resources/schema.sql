drop table if exists users;

create table users (
    username varchar(50) not null primary key,
    password varchar(500) not null,
    enabled boolean not null
);


drop table if exists authorities;

create table authorities (
    username varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_user foreign key (username) references users (username)
);

create unique index ix_auth_username on authorities (username, authority);



