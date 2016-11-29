#!/usr/bin/env python3
# coding: utf-8


import abc
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
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization as crypto_serial
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from sqlalchemy import orm
from sqlalchemy.ext import declarative


class Application:
    def run(self):
        print('Working...')
        config = Config()
        with GitContentSource(config.content_repo_url) as content_source:
            with DatabaseCollection(
                config.current_schema_info_dir,
                config.migration_script_dir,
                content_source
            ) as databases:
                Publisher().publish(
                    content_source.version,
                    databases,
                    FileUtils.read_binary(config.signature_key_file_path),
                    config.publish_url
                )


class Config:
    ConfigKey = collections.namedtuple('ConfigKey', ['section', 'option'])

    CONFIG_FILE_NAME = 'config.ini'

    CURRENT_SCHEMA_INFO_SUBDIR = 'schema'
    MIGRATION_SCRIPT_SUBDIR = 'migrations'

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
    def current_schema_info_dir(self):
        return os.path.join(
            self._get_script_dir(), self.CURRENT_SCHEMA_INFO_SUBDIR
        )

    @property
    def migration_script_dir(self):
        return os.path.join(
            self._get_script_dir(), self.MIGRATION_SCRIPT_SUBDIR
        )

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
        return os.path.expanduser(
            self._get_option(self.SIGNATURE_KEY_FILE_PATH_KEY)
        )

    @property
    def publish_url(self):
        return self._get_option(self.PUBLISH_URL_KEY)


class GitContentSource:
    STOP_DIR = 'content/stops'
    ROUTE_DIR = 'content/routes'

    STOPS_ROOT_KEY = 'stops'
    ROUTES_ROOT_KEY = 'routes'

    def __init__(self, repo_url):
        self._repo_url = repo_url
        self._content_dir_context = tempfile.TemporaryDirectory()

        self._loaded = False
        self._version = None
        self._route_item_source = None
        self._stop_item_source = None

    def __enter__(self):
        self._content_dir = self._content_dir_context.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._content_dir_context.__exit__(exc_type, exc_val, exc_tb)

    @property
    def version(self):
        self._ensure_loaded()
        return self._version

    def _ensure_loaded(self):
        if self._loaded:
            return

        self._clone()

        self._version = self._read_version()
        self._route_item_source = self._get_yaml_item_source(
            self.ROUTE_DIR, self.ROUTES_ROOT_KEY
        )
        self._stop_item_source = self._get_yaml_item_source(
            self.STOP_DIR, self.STOPS_ROOT_KEY
        )

        self._loaded = True

    def _clone(self):
        subprocess.run(
            ['git', 'clone', '--depth=1', self._repo_url, self._content_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    def _read_version(self):
        with CurrentDir(self._content_dir):
            return subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            ).strip()

    def _get_yaml_item_source(self, item_subdir, item_root_key):
        route_dir = os.path.join(self._content_dir, item_subdir)
        return FileYamlItemSource(route_dir, item_root_key)

    @property
    def route_item_source(self):
        self._ensure_loaded()
        return self._route_item_source

    @property
    def stop_item_source(self):
        self._ensure_loaded()
        return self._stop_item_source


class CurrentDir:
    def __init__(self, target_dir):
        self._target_dir = target_dir

    def __enter__(self):
        self._original_dir = os.getcwd()
        os.chdir(self._target_dir)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self._original_dir)


class DatabaseCollection:
    def __init__(self, current_schema_info_dir, migration_script_dir,
                 content_source):
        self._current_schema_info_dir = current_schema_info_dir
        self._migration_script_dir = migration_script_dir
        self._content_source = content_source

        self._target_dir_context = tempfile.TemporaryDirectory()

    def __enter__(self):
        self._target_dir = self._target_dir_context.__enter__()
        return self.get()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._target_dir_context.__exit__(exc_type, exc_val, exc_tb)

    def get(self):
        current_schema_database = CurrentSchemaDatabase(
            self._target_dir,
            self._current_schema_info_dir,
            self._content_source
        )
        yield current_schema_database

        yield from self._get_old_schema_databases(
            current_schema_database.schema_version
        )

    def _get_old_schema_databases(self, current_schema_version):
        migrations = OldSchemaDatabase.get_migrations(
            current_schema_version, self._migration_script_dir
        )
        return (
            OldSchemaDatabase(self._target_dir, self._migration_script_dir, x)
            for x in migrations
        )


class Database(abc.ABC):
    DATABASE_OPTIMIZATION_SCRIPT = '''
        vacuum;
        analyze;
        reindex;
    '''
    DATABASE_FILE_TEMPLATE = '{}.db'

    @property
    @abc.abstractmethod
    def content(self):
        pass

    @property
    @abc.abstractmethod
    def schema_version(self):
        pass

    def _execute_script(self, connection, script_file_path):
        connection.executescript(FileUtils.read_text(script_file_path))

    def _optimize_database(self, file_path):
        with sqlite3.connect(file_path) as connection:
            connection.executescript(self.DATABASE_OPTIMIZATION_SCRIPT)

    def _get_database_file_name(self, schema_version):
        return self.DATABASE_FILE_TEMPLATE.format(schema_version)


class FileUtils:
    @classmethod
    def read_binary(cls, file_path):
        with open(file_path, mode='rb') as f:
            return f.read()

    @classmethod
    def read_text(cls, file_path, encoding='utf-8'):
        with open(file_path, mode='r', encoding=encoding) as f:
            return f.read()


class CurrentSchemaDatabase(Database):
    SCHEMA_VERSION_FILE = 'version.txt'
    TABLES_SCRIPT_FILE = 'tables.sql'
    INDICES_SCRIPT_FILE = 'indices.sql'

    def __init__(self, target_dir, schema_info_dir, content_source):
        self._schema_version = self._read_schema_version(schema_info_dir)
        self._file_path = os.path.join(
            target_dir, self._get_database_file_name(self._schema_version)
        )
        self._create_database(schema_info_dir, content_source)

    def _read_schema_version(self, schema_info_dir):
        file_path = os.path.join(schema_info_dir, self.SCHEMA_VERSION_FILE)
        return SchemaVersion.from_file(file_path).get_as_int()

    @property
    def content(self):
        return FileUtils.read_binary(self._file_path)

    @property
    def schema_version(self):
        return self._schema_version

    def _create_database(self, schema_script_dir, content_source):
        self._create_database_schema(schema_script_dir)
        self._populate_database(content_source)
        self._optimize_database(self._file_path)

    def _create_database_schema(self, schema_script_dir):
        with sqlite3.connect(self._file_path) as connection:
            for file in (self.TABLES_SCRIPT_FILE, self.INDICES_SCRIPT_FILE):
                self._execute_script(
                    connection, os.path.join(schema_script_dir, file)
                )

    def _populate_database(self, content_source):
        builder = CurrentSchemaDatabaseBuilder()
        with Session(self._file_path) as session:
            TripType.init(session)
            stops = list(
                builder.build_stops(content_source.stop_item_source)
            )
            session.add_all(stops)

            built_routes = builder.build_routes(
                content_source.route_item_source
            )
            for built_route in built_routes:
                session.add(built_route.route)
                session.add_all(builder.build_route_stops(built_route, stops))
                session.add_all(builder.build_trips(built_route))


class SchemaVersion:
    MIN_SCHEMA_VERSION = 1
    MAX_SCHEMA_VERSION = 2 ** 31 - 1

    @classmethod
    def from_text(cls, schema_version_text):
        return SchemaVersion(schema_version_text)

    @classmethod
    def from_file(cls, file_path):
        return cls.from_text(FileUtils.read_text(file_path))

    def __init__(self, schema_version_text):
        try:
            self._schema_version = self._get_schema_version(schema_version_text)
        except ValueError:
            raise ValueError(
                'Invalid schema version: “{}”.'.format(schema_version_text)
            )

    def _get_schema_version(self, schema_version_text):
        schema_version = int(schema_version_text)

        if not self._is_valid_schema_version(schema_version):
            raise ValueError()

        return schema_version

    def _is_valid_schema_version(self, schema_version):
        return (self.MIN_SCHEMA_VERSION <= schema_version <=
                self.MAX_SCHEMA_VERSION)

    def get_as_int(self):
        return self._schema_version


BuiltRoute = collections.namedtuple('BuiltRoute', ['route_item', 'route'])


class CurrentSchemaDatabaseBuilder:
    class StopItem:
        KEY = 'key'
        NAME = 'name'
        DIRECTION = 'direction'
        LATITUDE = 'latitude'
        LONGITUDE = 'longitude'

    class RouteItem:
        HIDDEN = 'hidden'
        NUMBER = 'number'
        DESCRIPTION = 'description'
        STOPS = 'stops'
        TRIPS = 'trips'

        class Stop:
            KEY = 'key'
            SHIFT = 'shift'

        class Trip:
            WORKDAYS = 'workdays'
            WEEKEND = 'weekend'
            EVERYDAY = 'everyday'

    def build_stops(self, stop_item_source):
        return (self._build_stop(x) for x in stop_item_source.get())

    def _build_stop(self, stop_item):
        return Stop(
            key=stop_item[self.StopItem.KEY],
            name=stop_item[self.StopItem.NAME],
            direction=stop_item.get(self.StopItem.DIRECTION),
            latitude=stop_item[self.StopItem.LATITUDE],
            longitude=stop_item[self.StopItem.LONGITUDE]
        )

    def build_routes(self, route_item_source):
        for route_item in self._get_route_items(route_item_source.get()):
            route = self._build_route(route_item)
            yield BuiltRoute(route_item=route_item, route=route)

    def _get_route_items(self, route_items):
        return (x for x in route_items if not x.get(self.RouteItem.HIDDEN))

    def _build_route(self, route_item):
        return Route(
            number=route_item[self.RouteItem.NUMBER],
            description=route_item[self.RouteItem.DESCRIPTION]
        )

    def build_route_stops(self, built_route, stops):
        for stop_item in built_route.route_item[self.RouteItem.STOPS]:
            stop = Stop.find_by_key(stops, stop_item[self.RouteItem.Stop.KEY])
            yield self._build_route_stop(stop_item, built_route.route, stop)

    def _build_route_stop(self, route_stop_item, route, stop):
        shift_time = YamlTime.create(
            route_stop_item[self.RouteItem.Stop.SHIFT]
        )
        return RouteStop(
            route=route,
            stop=stop,
            shift_hour=shift_time.hour,
            shift_minute=shift_time.minute
        )

    def build_trips(self, built_route):
        for trip_type_key, trip_type in self._get_trip_types():
            yield from self._build_trips_of_type(
                built_route, trip_type_key, trip_type
            )

    def _get_trip_types(self):
        return (
            (self.RouteItem.Trip.WORKDAYS, TripType.work_days),
            (self.RouteItem.Trip.WEEKEND,  TripType.weekend),
            (self.RouteItem.Trip.EVERYDAY, TripType.everyday)
        )

    def _build_trips_of_type(self, built_route, trip_type_key, trip_type):
        trip_groups = built_route.route_item[self.RouteItem.TRIPS]
        for trip_item in (trip_groups.get(trip_type_key) or list()):
            trip_time = YamlTime.create(trip_item)
            yield Trip(
                type=trip_type,
                route=built_route.route,
                hour=trip_time.hour,
                minute=trip_time.minute
            )


class YamlItemSource(abc.ABC):
    @abc.abstractmethod
    def get(self):
        pass


class FileYamlItemSource(YamlItemSource):
    YAML_SUFFIX = '.yaml'

    def __init__(self, source_dir, root_key):
        self._source_dir = source_dir
        self._root_key = root_key

    def get(self):
        doc_files = (
            os.path.join(self._source_dir, x)
            for x in os.listdir(self._source_dir)
        )
        docs = (
            FileUtils.read_text(x) for x in doc_files
            if os.path.splitext(x)[1] == self.YAML_SUFFIX and os.path.isfile(x)
        )

        return StringYamlItemSource(docs, self._root_key).get()


class StringYamlItemSource(YamlItemSource):
    def __init__(self, docs, root_key):
        self._docs = docs
        self._root_key = root_key

    def get(self):
        result = []
        for doc in self._docs:
            result += self._read_doc(doc)
        return result

    def _read_doc(self, doc):
        loaded_dict = yaml.safe_load(doc)
        return loaded_dict[self._root_key]


class YamlTime(abc.ABC):
    def __init__(self):
        self._hour = None
        self._minute = None

    @classmethod
    def create(cls, source_value):
        # Time scalar might get parsed as an sexagesimal integer
        # (see http://yaml.org/spec/spec.html#id2561981)
        if isinstance(source_value, int):
            return IntYamlTime(source_value)
        elif isinstance(source_value, str):
            return StringYamlTime(source_value)
        else:
            raise ValueError()

    @abc.abstractmethod
    def _parse(self):
        pass

    @property
    def hour(self):
        if not self._hour:
            self._parse()
        return self._hour

    @property
    def minute(self):
        if not self._minute:
            self._parse()
        return self._minute


class StringYamlTime(YamlTime):
    def __init__(self, source_string):
        super().__init__()
        self._source_string = source_string

    def _parse(self):
        try:
            if len(self._source_string) != len('hh:mm'):
                raise ValueError()
        except:
            raise

        self._hour = self._to_positive_int(self._source_string[0:2])

        separator = self._source_string[2:3]
        if separator != ':':
            raise ValueError()

        self._minute = self._to_positive_int(self._source_string[3:5])
        if not 0 <= self._minute <= 59:
            raise ValueError()

    def _to_positive_int(self, string_value):
        int_value = int(string_value)

        if int_value < 0:
            raise ValueError()

        return int_value


class IntYamlTime(YamlTime):
    MIN_PER_HOUR = 60

    def __init__(self, source_int):
        super().__init__()
        self._source_int = source_int

    def _parse(self):
        self._hour = self._source_int // self.MIN_PER_HOUR
        self._minute = self._source_int % self.MIN_PER_HOUR


class Session:
    CONNECTION_STRING_TEMPLATE = 'sqlite+pysqlite:///{}'

    def __init__(self, db_file_path):
        session_class = orm.sessionmaker(
            bind=self._create_engine(self._create_db_url(db_file_path))
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


class TripType(Base):
    __tablename__ = 'TripTypes'

    everyday = None
    work_days = None
    weekend = None

    name = sa.Column(sa.Text, nullable=False)

    @classmethod
    def init(cls, session=None):
        cls.everyday = TripType(id=0, name='Не зависит от дня недели')
        cls.work_days = TripType(id=1, name='Работает только по рабочим дням')
        cls.weekend = TripType(id=2, name='Работает только по выходным дням')

        if session:
            session.add_all([cls.everyday, cls.work_days, cls.weekend])


class Route(Base):
    __tablename__ = 'Routes'

    number = sa.Column(sa.Text, nullable=False)
    description = sa.Column(sa.Text, nullable=False)


class Trip(Base):
    __tablename__ = 'Trips'

    type_id = sa.Column(sa.Integer, sa.ForeignKey('TripTypes._id'),
                        nullable=False)
    route_id = sa.Column(sa.Integer, sa.ForeignKey('Routes._id'),
                         nullable=False)
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

    route_id = sa.Column(sa.Integer, sa.ForeignKey('Routes._id'),
                         nullable=False)
    stop_id = sa.Column(sa.Integer, sa.ForeignKey('Stops._id'), nullable=False)
    shift_hour = sa.Column(sa.Integer, nullable=False)
    shift_minute = sa.Column(sa.Integer, nullable=False)

    route = orm.relationship(Route)
    stop = orm.relationship(Stop)


class OldSchemaDatabase(Database):
    MIGRATION_FILE_TEMPLATE = '{0:02d}-to-{1:02d}.sql'

    @classmethod
    def get_migrations(cls, current_schema_version, migration_script_dir):
        schema_version = current_schema_version
        while cls._can_migrate_from(schema_version, migration_script_dir):
            yield Migration(
                from_version=schema_version,
                to_version=schema_version - 1
            )
            schema_version -= 1

    @classmethod
    def _can_migrate_from(cls, source_version, migration_script_dir):
        if source_version - 1 < SchemaVersion.MIN_SCHEMA_VERSION:
            return False

        migration_script_path = cls._get_migration_script_path(
            source_version, migration_script_dir
        )
        return os.path.exists(migration_script_path)

    @classmethod
    def _get_migration_script_path(cls, source_version, migration_script_dir):
        return os.path.join(
            migration_script_dir,
            cls.MIGRATION_FILE_TEMPLATE.format(
                source_version, source_version - 1
            )
        )

    def __init__(self, target_dir, migration_script_dir, migration):
        self._schema_version = migration.to_version
        self._file_path = os.path.join(
            target_dir, self._get_database_file_name(self._schema_version)
        )
        self._migrate(target_dir, migration_script_dir, migration)

    @property
    def content(self):
        return FileUtils.read_binary(self._file_path)

    @property
    def schema_version(self):
        return self._schema_version

    def _migrate(self, target_dir, migration_script_dir, migration):
        with CurrentDir(target_dir):
            with sqlite3.connect(self._file_path) as connection:
                self._execute_script(
                    connection,
                    self._get_migration_script_path(
                        migration.from_version,
                        migration_script_dir
                    )
                )

        self._optimize_database(self._file_path)


Migration = collections.namedtuple('Migration', ['from_version', 'to_version'])


class Publisher:
    UTF8_ENCODING = 'utf-8'
    SIGNATURE_HEADER = 'X-Content-Signature'
    LOCATION_HEADER = 'Location'

    REDIRECTED_RESPONSE_TEMPLATE = (
        'Failed.\n'
        '{} {}.\n'
        'Request has been redirected from ‘{}’ to ‘{}’.'
    )
    SUCCEEDED_RESPONSE_MESSAGE = 'Done.'
    FAILED_RESPONSE_TEMPLATE = 'Failed.\n{}.'

    def publish(self, version, databases, private_key_binary, target_url):
        request_body = self._build_request_body(version, databases)
        signature = self._sign_request_body(
            request_body, private_key_binary
        )

        response = requests.post(
            target_url,
            headers={self.SIGNATURE_HEADER: signature},
            data=request_body.encode(self.UTF8_ENCODING),
            allow_redirects=False
        )
        self._handle_response(response)

    def _build_request_body(self, version, databases):
        request_body = dict(
            version=version,
            schema_versions=[
                dict(
                    schema_version=x.schema_version,
                    content=Base64.binary_to_base64_str(x.content)
                )
                for x in databases
            ]
        )

        return json.dumps(request_body)

    def _sign_request_body(self, request_body, private_key_binary):
        body_binary = request_body.encode(self.UTF8_ENCODING)
        signature_binary = Signature(private_key_binary).sign(body_binary)
        return Base64.binary_to_base64_str(signature_binary)

    def _handle_response(self, response):
        print(self._get_response_status_message(response))

    def _get_response_status_message(self, response):
        if response.is_redirect:
            return self.REDIRECTED_RESPONSE_TEMPLATE.format(
                response.status_code,
                response.reason,
                response.url,
                response.headers[self.LOCATION_HEADER]
            )
        if response.ok:
            return self.SUCCEEDED_RESPONSE_MESSAGE
        else:
            return self.FAILED_RESPONSE_TEMPLATE.format(response.text)


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


class Signature:
    def __init__(self, private_key_binary):
        self._private_key = crypto_serial.load_pem_private_key(
            private_key_binary, password=None, backend=crypto_backend()
        )

    def sign(self, message_binary):
        signer = self._private_key.signer(
            crypto_padding.PKCS1v15(), crypto_hashes.SHA512()
        )

        signer.update(message_binary)

        return signer.finalize()


if __name__ == '__main__':
    Application().run()
