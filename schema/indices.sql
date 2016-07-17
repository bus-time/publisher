create index TripsTypeIndex
  on Trips(type_id);

create index TripsRouteIndex
  on Trips(route_id);


create index RoutesAndStopsRouteIndex
  on RoutesAndStops(route_id);

create index RoutesAndStopsStopIndex
  on RoutesAndStops(stop_id);
