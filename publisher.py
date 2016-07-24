#!/usr/bin/env python3
# coding: utf-8


import base64
import collections
import configparser
import json
import os
import sqlite3
import subprocess
import tempfile

import requests
import sqlalchemy as sa
import yaml
from cryptography.hazmat.backends import default_backend as crypto_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization as crypto_serial
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from sqlalchemy import orm
from sqlalchemy.ext import declarative


class Application:
    def run(self):
        config = Config()

        with tempfile.TemporaryDirectory() as content_dir:
            self._clone_content(config.content_repo_url, content_dir)
            version = self._get_version(content_dir)

            with DatabaseCollection(config.script_dir, content_dir) as databases:
                Publisher(version, databases, config.signature_key_file_path, config.publish_url).publish()

    def _clone_content(self, source_url, target_dir):
        subprocess.run(['git', 'clone', '--depth=1', source_url, target_dir], check=True)

    def _get_version(self, repo_dir):
        with CurrentDir(repo_dir):
            return subprocess.check_output(['git', 'rev-parse', 'HEAD'], universal_newlines=True).strip()


class Config:
    ConfigKey = collections.namedtuple('ConfigKey', ['section', 'option'])

    CONFIG_FILE_NAME = 'config.ini'

    CONTENT_REPO_URL_KEY = ConfigKey('common', 'content-repo')
    SIGNATURE_KEY_FILE_PATH_KEY = ConfigKey('common', 'signature-key-file')
    PUBLISH_URL_KEY = ConfigKey('common', 'publish-url')

    def __init__(self):
        self._config_parser = self._get_config_parser()

    def _get_config_parser(self):
        parser = configparser.ConfigParser()
        parser.read(self._get_config_file_path())
        return parser

    def _get_config_file_path(self):
        return os.path.join(self._get_script_dir(), self.CONFIG_FILE_NAME)

    def _get_script_dir(self):
        return os.path.dirname(os.path.realpath(__file__))

    @property
    def script_dir(self):
        return self._get_script_dir()

    @property
    def content_repo_url(self):
        return self._get_option(self.CONTENT_REPO_URL_KEY)

    def _get_option(self, option_key):
        return self._config_parser.get(
            option_key.section,
            option_key.option
        )

    @property
    def signature_key_file_path(self):
        return os.path.expanduser(self._get_option(self.SIGNATURE_KEY_FILE_PATH_KEY))

    @property
    def publish_url(self):
        return self._get_option(self.PUBLISH_URL_KEY)


class DatabaseCollection:
    MIGRATIONS_DIR = 'migrations'
    SCHEMA_DIR = 'schema'
    VERSION_FILE = 'version.txt'
    TABLES_FILE = 'tables.sql'
    INDICES_FILE = 'indices.sql'

    ENCODING = 'utf8'

    MIN_SCHEMA_VERSION = 1
    MAX_SCHEMA_VERSION = 2 ** 31 - 1

    MIGRATION_FILE_TEMPLATE = '{0:02d}-to-{1:02d}.sql'
    DATABASE_FILE_TEMPLATE = '{}.db'

    def __init__(self, script_dir, content_dir):
        self._script_dir = script_dir
        self._content_dir = content_dir
        self._database_dir_context = tempfile.TemporaryDirectory()

    def __enter__(self):
        self._database_dir = self._database_dir_context.__enter__()
        return list(self._create_databases())

    def _create_databases(self):
        database = self._create_current_schema_database()
        yield database

        while self._can_migrate_from(database):
            database = self._migrate(database)
            yield database

    def _create_current_schema_database(self):
        schema_version = self._read_schema_version()
        file_path = self._get_database_file_path(schema_version)
        with sqlite3.connect(file_path) as connection:
            self._execute_sql(connection, self._get_schema_file_path(self.TABLES_FILE))
            self._execute_sql(connection, self._get_schema_file_path(self.INDICES_FILE))
        self._populate_database(file_path)

        return Database(file_path, schema_version)

    def _read_schema_version(self):
        schema_version_string = self._read_schema_version_string()

        try:
            return self._get_schema_version(schema_version_string)
        except ValueError:
            raise ValueError('Invalid schema version: “{}”.'.format(schema_version_string))

    def _read_schema_version_string(self):
        file_path = self._get_schema_file_path(self.VERSION_FILE)
        return self._read_text_file(file_path)

    def _get_schema_file_path(self, file_name):
        return os.path.join(self._script_dir, self.SCHEMA_DIR, file_name)

    def _read_text_file(self, file_path):
        with open(file_path, 'r', encoding=self.ENCODING) as f:
            return '\n'.join(f.readlines()).strip()

    def _get_schema_version(self, schema_version_string):
        schema_version = int(schema_version_string)

        if not self._is_valid_schema_version(schema_version):
            raise ValueError()

        return schema_version

    def _is_valid_schema_version(self, schema_version):
        return (self.MIN_SCHEMA_VERSION <= schema_version <=
                self.MAX_SCHEMA_VERSION)

    def _get_database_file_path(self, schema_version):
        return os.path.join(
            self._database_dir,
            self.DATABASE_FILE_TEMPLATE.format(schema_version)
        )

    def _execute_sql(self, connection, script_file_path):
        connection.executescript(self._read_text_file(script_file_path))

    def _populate_database(self, database_file_path):
        DatabaseContent(self._content_dir).populate_database(database_file_path)

    def _can_migrate_from(self, database):
        if database.schema_version - 1 < self.MIN_SCHEMA_VERSION:
            return False

        if not os.path.exists(self._get_migration_script_path(database.schema_version)):
            return False

        return True

    def _get_migration_script_path(self, source_version):
        return os.path.join(
            self._script_dir,
            self.MIGRATIONS_DIR,
            self.MIGRATION_FILE_TEMPLATE.format(source_version, source_version - 1)
        )

    def _migrate(self, source_database):
        with CurrentDir(self._database_dir):
            target_schema_version = source_database.schema_version - 1
            file_path = self._get_database_file_path(target_schema_version)

            with sqlite3.connect(file_path) as connection:
                self._execute_sql(
                    connection, self._get_migration_script_path(source_database.schema_version)
                )

            return Database(file_path, target_schema_version)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._database_dir_context.__exit__(exc_type, exc_val, exc_tb)


class Database:
    def __init__(self, file_path, schema_version):
        self.file_path = file_path
        self.schema_version = schema_version


class DatabaseContent:
    STOP_DIR = 'content/stops'
    ROUTE_DIR = 'content/routes'
    YAML_SUFFIX = '.yaml'

    STOPS_ROOT_KEY = 'stops'
    ROUTES_ROOT_KEY = 'routes'

    ENCODING = 'utf8'

    MIN_PER_HOUR = 60

    def __init__(self, content_dir):
        self._content_dir = content_dir

    def populate_database(self, database_file_path):
        with Session(database_file_path) as session:
            TripType.init(session)

            stops = self._build_stops()
            session.add_all(stops)

            self._populate_routes(session, stops)

    def _build_stops(self):
        return [self._build_stop(x) for x in self._read_stop_items()]

    def _build_stop(self, stop_item):
        return Stop(
            key=stop_item['key'],
            name=stop_item['name'],
            direction=stop_item.get('direction'),
            latitude=stop_item['latitude'],
            longitude=stop_item['longitude']
        )

    def _read_stop_items(self):
        return self._read_yaml_items(self.STOP_DIR, self.STOPS_ROOT_KEY)

    def _read_yaml_items(self, dir_name, root_item_name):
        dir_path = os.path.join(self._content_dir, dir_name)

        item_files = [os.path.join(dir_path, x) for x in os.listdir(dir_path)]
        item_files = [
            x for x in item_files
            if os.path.splitext(x)[1] == self.YAML_SUFFIX and os.path.isfile(x)
            ]
        items = list()
        for item_file in item_files:
            self._read_item_file(items, item_file, root_item_name)

        return items

    def _read_item_file(self, target_list, item_file, root_item_name):
        with open(item_file, 'r', encoding=self.ENCODING) as f:
            loaded_dict = yaml.safe_load(f)
            target_list += loaded_dict[root_item_name]

    def _populate_routes(self, session, stops):
        for route_item in self._read_route_items():
            if route_item.get('hidden'):
                continue

            route = self._build_route(route_item)
            session.add(route)

            self._populate_route_stops(session, route_item, route, stops)
            self._populate_trips(session, route_item, route)

    def _read_route_items(self):
        return self._read_yaml_items(self.ROUTE_DIR, self.ROUTES_ROOT_KEY)

    def _build_route(self, route_item):
        return Route(
            number=route_item['number'],
            description=route_item['description']
        )

    def _populate_route_stops(self, session, route_item, route, stops):
        for stop_item in route_item['stops']:
            stop = Stop.find_by_key(stops, stop_item['key'])
            shift_hour, shift_minute = self._parse_time(stop_item['shift'])
            route_stop = RouteStop(
                route=route,
                stop=stop,
                shift_hour=shift_hour,
                shift_minute=shift_minute
            )
            session.add(route_stop)

    def _parse_time(self, time_value):
        # Time scalar might get parsed as an sexagesimal integer
        # (see http://yaml.org/spec/spec.html#id2561981)
        if isinstance(time_value, int):
            return self._parse_time_as_int(time_value)
        elif isinstance(time_value, str):
            return self._parse_time_as_string(time_value)
        else:
            raise ValueError()

    def _parse_time_as_int(self, time_int):
        return time_int // self.MIN_PER_HOUR, time_int % self.MIN_PER_HOUR

    def _parse_time_as_string(self, time_string):
        try:
            if len(time_string) != len('hh:mm'):
                raise ValueError()
        except:
            raise

        hour = self._to_positive_int(time_string[0:2])

        separator = time_string[2:3]
        if separator != ':':
            raise ValueError()

        minute = self._to_positive_int(time_string[3:5])
        if not 0 <= minute <= 59:
            raise ValueError()

        return hour, minute

    def _to_positive_int(self, string_value):
        int_value = int(string_value)

        if int_value < 0:
            raise ValueError()

        return int_value

    def _populate_trips(self, session, route_item, route):
        trip_types = [
            ('workdays', TripType.work_days),
            ('weekend', TripType.weekend),
            ('everyday', TripType.everyday)
        ]

        for trip_type_key, trip_type in trip_types:
            self._populate_trips_of_type(
                session, route_item, route, trip_type_key, trip_type
            )

    def _populate_trips_of_type(self, session, route_item, route, trip_type_key, trip_type):
        for trip_item in (route_item['trips'].get(trip_type_key) or list()):
            hour, minute = self._parse_time(trip_item)
            trip = Trip(
                type=trip_type,
                route=route,
                hour=hour,
                minute=minute
            )
            session.add(trip)


class CurrentDir:
    def __init__(self, target_dir):
        self._target_dir = target_dir

    def __enter__(self):
        self._original_dir = os.getcwd()
        os.chdir(self._target_dir)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self._original_dir)


class Session:
    CONNECTION_STRING_TEMPLATE = 'sqlite+pysqlite:///{}'

    def __init__(self, file_path):
        session_class = orm.sessionmaker(
            bind=self._create_engine(self._create_db_url(file_path))
        )

        self._session = session_class()

    def _create_db_url(self, file_path):
        return self.CONNECTION_STRING_TEMPLATE.format(file_path)

    def _create_engine(self, db_url):
        return sa.create_engine(db_url)

    def __enter__(self):
        return self._session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._session.rollback()
        else:
            self._session.commit()
        self._session.close()


class Base:
    id = sa.Column('_id', sa.Integer, primary_key=True, autoincrement=True)


Base = declarative.declarative_base(cls=Base)


class Route(Base):
    __tablename__ = 'Routes'

    number = sa.Column(sa.Text, nullable=False)
    description = sa.Column(sa.Text, nullable=False)


class TripType(Base):
    __tablename__ = 'TripTypes'

    everyday = None
    work_days = None
    weekend = None

    name = sa.Column(sa.Text, nullable=False)

    @classmethod
    def init(cls, session):
        cls.everyday = TripType(id=0, name='Не зависит от дня недели')
        cls.work_days = TripType(id=1, name='Работает только по рабочим дням')
        cls.weekend = TripType(id=2, name='Работает только по выходным дням')

        session.add_all([cls.everyday, cls.work_days, cls.weekend])


class Trip(Base):
    __tablename__ = 'Trips'

    type_id = sa.Column(sa.Integer, sa.ForeignKey('TripTypes._id'), nullable=False)
    route_id = sa.Column(sa.Integer, sa.ForeignKey('Routes._id'), nullable=False)
    hour = sa.Column(sa.Integer, nullable=False)
    minute = sa.Column(sa.Integer, nullable=False)

    type = orm.relationship(TripType)
    route = orm.relationship(Route)


class Stop(Base):
    __tablename__ = 'Stops'

    name = sa.Column(sa.Text, nullable=False)
    direction = sa.Column(sa.Text, nullable=Trip)
    latitude = sa.Column(sa.Float, nullable=False)
    longitude = sa.Column(sa.Float, nullable=False)

    def __init__(self, key, name, direction, latitude, longitude):
        self.key = key
        self.name = name
        self.direction = direction
        self.latitude = latitude
        self.longitude = longitude

    @classmethod
    def find_by_key(cls, stops, key):
        filtered = [x for x in stops if x.key == key]
        if len(filtered) != 1:
            raise KeyError()

        return filtered[0]


class RouteStop(Base):
    __tablename__ = 'RoutesAndStops'

    route_id = sa.Column(sa.Integer, sa.ForeignKey('Routes._id'), nullable=False)
    stop_id = sa.Column(sa.Integer, sa.ForeignKey('Stops._id'), nullable=False)
    shift_hour = sa.Column(sa.Integer, nullable=False)
    shift_minute = sa.Column(sa.Integer, nullable=False)

    route = orm.relationship(Route)
    stop = orm.relationship(Stop)


class Publisher:
    UTF8_ENCODING = 'utf-8'
    SIGNATURE_HEADER = 'X-Content-Signature'

    def __init__(self, version, databases, key_file_path, target_url):
        self._version = version
        self._databases = databases
        self._key_file_path = key_file_path
        self._target_url = target_url

    def publish(self):
        content_json = self._build_content_json()
        content_signature = self._sign_content(content_json, self._key_file_path)

        response = requests.post(
            self._target_url,
            headers={self.SIGNATURE_HEADER: content_signature},
            data=content_json.encode(self.UTF8_ENCODING)
        )
        print(response)

    def _build_content_json(self):
        content = dict(
            version=self._version,
            schema_versions=[
                dict(
                    schema_version=x.schema_version,
                    content=Base64.binary_to_base64_str(self._read_binary_file(x.file_path))
                )
                for x in self._databases
                ]
        )

        return json.dumps(content)

    def _read_binary_file(self, file_path):
        with open(file_path, 'rb') as f:
            return f.read()

    def _sign_content(self, content_json, key_file_path):
        key_binary = self._read_binary_file(key_file_path)

        private_key = crypto_serial.load_pem_private_key(
            key_binary, password=None, backend=crypto_backend()
        )
        signer = private_key.signer(
            crypto_padding.PKCS1v15(), crypto_hashes.SHA512()
        )

        signer.update(content_json.encode(self.UTF8_ENCODING))

        return Base64.binary_to_base64_str(signer.finalize())


class Base64:
    ASCII_ENCODING = 'ascii'

    @classmethod
    def binary_to_base64_str(cls, binary):
        if binary is None:
            return None

        return base64.b64encode(binary).decode(cls.ASCII_ENCODING)

    @classmethod
    def base64_str_to_binary(cls, base64_str):
        if base64_str is None:
            return None

        return base64.b64decode(base64_str.encode(cls.ASCII_ENCODING))


if __name__ == '__main__':
    Application().run()
