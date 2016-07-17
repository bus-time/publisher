attach database "2.db" as next;

begin transaction;


-- Schema

create table if not exists Routes (
  _id integer primary key not null unique,
  name text not null unique
);


create table if not exists TripTypes (
  _id integer primary key not null unique,
  name text not null unique
);


create table if not exists Trips (
  _id integer primary key autoincrement not null unique,
  trip_type_id integer not null references TripTypes(_id),
  route_id integer not null references Routes(_id),
  departure_time text not null
);


create table if not exists Stations (
  _id integer primary key not null unique,
  name text not null unique,
  latitude text not null,
  longitude text not null
);


create table if not exists RoutesAndStations (
  _id integer primary key autoincrement not null unique,
  route_id integer not null references Routes(_id),
  station_id integer not null references Stations(_id),
  time_shift text not null
);


-- Migrations

insert into Routes
(
  _id,
  name
)
select
  _id,
  number || " " || "(" || description || ")"
from next.Routes;


insert into TripTypes
(
  _id,
  name
)
select
  _id,
  name
from next.TripTypes;


insert into Trips
(
  _id,
  trip_type_id,
  route_id,
  departure_time
)
select
  _id,
  type_id,
  route_id,
  strftime("%H:%M", "00:00", hour || " " || "hours", minute || " " || "minutes")
from next.Trips;


insert into Stations
(
  _id,
  name,
  latitude,
  longitude
)
select
  _id,
  case
    when direction is null then name
    else name || " " || "(" || direction || ")"
  end,
  latitude,
  longitude
from next.Stops;


insert into RoutesAndStations
(
  route_id,
  station_id,
  time_shift
)
select
  route_id,
  stop_id,
  strftime("%H:%M", "00:00", shift_hour || " " || "hours", shift_minute || " " || "minutes")
from next.RoutesAndStops;


commit transaction;

detach database next;
