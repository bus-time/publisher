create table Routes (
  _id integer primary key not null unique,
  number text not null,
  description text not null
);


create table TripTypes (
  _id integer primary key not null unique,
  name text not null unique
);


create table Trips (
  _id integer primary key autoincrement not null unique,
  type_id integer not null references TripTypes(_id),
  route_id integer not null references Routes(_id),
  hour integer not null,
  minute integer not null
);


create table Stops (
  _id integer primary key not null unique,
  name text not null,
  direction text,
  latitude real not null,
  longitude real not null
);


create table RoutesAndStops (
  route_id integer not null references Routes(_id),
  stop_id integer not null references Stops(_id),
  shift_hour integer not null,
  shift_minute integer not null
);
