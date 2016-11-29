# coding: utf-8


import json
import os
import subprocess
import tempfile

import httpretty
import pytest
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.backends import default_backend as crypto_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization as crypto_serial
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding

import publisher as pub


class TestGitContentSource:
    def test_cloning_and_version_succeeds(self):
        with tempfile.TemporaryDirectory() as source_repo_dir:
            self._create_test_repo(source_repo_dir)
            expected_version = self._get_expected_version(source_repo_dir)

            with pub.GitContentSource('file://' + source_repo_dir) as source:
                assert source.version == expected_version

    def _create_test_repo(self, repo_dir):
        self._create_test_file(repo_dir)
        self._init_repo(repo_dir)

    def _create_test_file(self, repo_dir):
        with open(os.path.join(repo_dir, 'test'), mode='w') as f:
            f.write('test')

    def _init_repo(self, repo_dir):
        with pub.CurrentDir(repo_dir):
            self._exec_git(['init'])
            self._exec_git(['add', '--all'])
            self._exec_git(['commit', '-m', 'test'])

    def _exec_git(self, args):
        subprocess.run(['git'] + args)

    def _get_expected_version(self, repo_dir):
        with pub.CurrentDir(repo_dir):
            return subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], universal_newlines=True
            ).strip()

    def test_no_double_cloning_on_multiple_access(self):
        with tempfile.TemporaryDirectory() as source_repo_dir:
            self._create_test_repo(source_repo_dir)

            with pub.GitContentSource('file://' + source_repo_dir) as source:
                assert source.version is not None
                assert source.version is not None


class TestCurrentDir:
    def test_succeeds(self):
        with tempfile.TemporaryDirectory() as base_dir:
            original_dir = os.path.join(base_dir, 'original')
            os.mkdir(original_dir)

            target_dir = os.path.join(base_dir, 'target')
            os.mkdir(target_dir)

            os.chdir(original_dir)

            assert original_dir == os.getcwd()
            with pub.CurrentDir(target_dir):
                assert target_dir == os.getcwd()
            assert original_dir == os.getcwd()


class TestSchemaVersion:
    def test_valid_succeeds(self):
        assert self._parse('15') == 15

    def _parse(self, schema_version_text):
        return pub.SchemaVersion.from_text(schema_version_text).get_as_int()

    def test_not_int_fails(self):
        self._assert_parse_fails('something')

    def _assert_parse_fails(self, schema_version_text):
        with pytest.raises(ValueError) as ex_info:
            self._parse(schema_version_text)
        assert 'Invalid schema version' in str(ex_info)

    def test_zero_int_fails(self):
        self._assert_parse_fails('0')

    def test_negative_int_fails(self):
        self._assert_parse_fails('-5')

    def test_too_big_int_fails(self):
        self._assert_parse_fails(str(2 ** 31))


class TestCurrentSchemaDatabaseBuilder:
    STOPS_YAML = '''
        stops:
          - key: koptevo-to-polotsk
            name: Коптево
            direction: в Полоцк
            latitude: 55.539927
            longitude: 28.668764
          - key: koptevo-from-polotsk
            name: Коптево
            direction: из Полоцка
            latitude: 55.540719
            longitude: 28.670223
        '''

    ROUTES_YAML = '''
        routes:
          - number: 2
            description: Подкастельцы → ОАО «Нафтан»
            stops:
              - key: koptevo-to-polotsk
                shift: 00:02
              - key: koptevo-from-polotsk
                shift: 00:03
            trips:
              workdays:
                - 05:40
                - 05:52
              weekend:
                - 12:20
                - 14:00
              everyday:
                - 05:13
                - 06:10
          - number: 6
            description: Новополоцк → Боровуха
            stops:
              - key: koptevo-to-polotsk
                shift: 00:00
              - key: koptevo-from-polotsk
                shift: 00:06
            trips:
              everyday:
                - 05:13
                - 06:10
        '''

    def test_build_stops_succeeds(self):
        stops = self._build_stops()

        assert len(stops) == 2
        self._assert_stop(
            stops[0],
            'koptevo-to-polotsk',
            'Коптево',
            'в Полоцк',
            55.539927,
            28.668764
        )
        self._assert_stop(
            stops[1],
            'koptevo-from-polotsk',
            'Коптево',
            'из Полоцка',
            55.540719,
            28.670223
        )

    def _build_stops(self):
        stop_item_source = pub.StringYamlItemSource([self.STOPS_YAML], 'stops')
        return list(
            pub.CurrentSchemaDatabaseBuilder().build_stops(stop_item_source)
        )

    def _assert_stop(self, stop, key, name, direction, latitude, longitude):
        assert isinstance(stop, pub.Stop)
        assert stop.key == key
        assert stop.name == name
        assert stop.direction == direction
        assert stop.latitude == latitude
        assert stop.longitude == longitude

    def test_build_routes_succeeds(self):
        built_routes = self._build_routes()

        assert len(built_routes) == 2
        self._assert_built_route(
            built_routes[0], 2, 'Подкастельцы → ОАО «Нафтан»'
        )
        self._assert_built_route(
            built_routes[1], 6, 'Новополоцк → Боровуха'
        )

    def _build_routes(self):
        route_item_source = pub.StringYamlItemSource(
            [self.ROUTES_YAML], 'routes'
        )
        return list(
            pub.CurrentSchemaDatabaseBuilder().build_routes(route_item_source)
        )

    def _assert_built_route(self, built_route, number, description):
        assert isinstance(built_route, pub.BuiltRoute)
        assert isinstance(built_route.route_item, dict)
        assert isinstance(built_route.route, pub.Route)

        assert built_route.route_item['number'] == number
        assert built_route.route_item['description'] == description

        assert built_route.route.number == number
        assert built_route.route.description == description

    def test_build_route_stops_succeeds(self):
        stops = self._build_stops()
        built_route = self._build_routes()[0]

        route_stops = list(
            pub.CurrentSchemaDatabaseBuilder().build_route_stops(
                built_route, stops
            )
        )

        assert len(route_stops) == 2

        self._assert_route_stop(
            route_stops[0], built_route.route, stops[0], 0, 2
        )
        self._assert_route_stop(
            route_stops[1], built_route.route, stops[1], 0, 3
        )

    def _assert_route_stop(self, route_stop, route, stop, shift_hour,
                           shift_minute):
        assert route_stop.route == route
        assert route_stop.stop == stop
        assert route_stop.shift_hour == shift_hour
        assert route_stop.shift_minute == shift_minute

    def test_build_trips_succeeds(self):
        pub.TripType.init()
        built_route = self._build_routes()[0]
        trips = list(
            pub.CurrentSchemaDatabaseBuilder().build_trips(built_route)
        )

        assert len(trips) == 6

        self._assert_trip(
            trips[0], pub.TripType.work_days, built_route.route, 5, 40
        )
        self._assert_trip(
            trips[1], pub.TripType.work_days, built_route.route, 5, 52
        )
        self._assert_trip(
            trips[2], pub.TripType.weekend, built_route.route, 12, 20
        )
        self._assert_trip(
            trips[3], pub.TripType.weekend, built_route.route, 14, 0
        )
        self._assert_trip(
            trips[4], pub.TripType.everyday, built_route.route, 5, 13
        )
        self._assert_trip(
            trips[5], pub.TripType.everyday, built_route.route, 6, 10
        )

    def _assert_trip(self, trip, trip_type, route, hour, minute):
        assert isinstance(trip, pub.Trip)
        assert trip.type == trip_type
        assert trip.route == route
        assert trip.hour == hour
        assert trip.minute == minute


class TestStringYamlItemSource:
    def test_single_load_succeeds(self):
        expected = [
            dict(
                key='koptevo-to-borovuha',
                name='Коптево',
                latitude=55.542185
            ),
            dict(
                key='koptevo-from-borovuha',
                name='Коптево',
                latitude=55.5418
            ),
        ]
        source = [
            '''
            stops:
              - key: koptevo-to-borovuha
                name: Коптево
                latitude: 55.542185
              - key: koptevo-from-borovuha
                name: Коптево
                latitude: 55.5418
            '''
        ]

        self._assert_load_succeeds(expected, source)

    def _assert_load_succeeds(self, expected, source):
        actual = self._load_docs(source)
        self._assert_lists_are_equal(expected, actual)

    def _load_docs(self, docs):
        return pub.StringYamlItemSource(docs, 'stops').get()

    def _assert_lists_are_equal(self, expected, actual):
        assert isinstance(expected, list)
        assert isinstance(actual, list)
        assert len(expected) == len(actual)

        for index in range(0, len(expected)):
            self._assert_items_are_equal(expected[index], actual[index])

    def _assert_items_are_equal(self, expected, actual):
        for key in ['key', 'name', 'latitude']:
            assert expected[key] == actual[key]

    def test_multiple_load_succeeds(self):
        expected = [
            dict(
                key='koptevo-to-borovuha',
                name='Коптево',
                latitude=55.542185
            ),
            dict(
                key='koptevo-from-borovuha',
                name='Коптево',
                latitude=55.5418
            ),
        ]
        source = [
            '''
            stops:
              - key: koptevo-to-borovuha
                name: Коптево
                latitude: 55.542185
            ''',
            '''
            stops:
              - key: koptevo-from-borovuha
                name: Коптево
                latitude: 55.5418
            '''
        ]

        self._assert_load_succeeds(expected, source)

    def test_no_source_load_succeeds(self):
        expected = []
        source = []
        self._assert_load_succeeds(expected, source)


class TestYamlTime:
    def test_string_time_parse_succeeds(self):
        time = pub.YamlTime.create('08:45')

        assert isinstance(time, pub.StringYamlTime)
        assert time.hour == 8
        assert time.minute == 45

    def test_int_time_parse_succeeds(self):
        time = pub.YamlTime.create(14 * 60 + 38)  # 14:38

        assert isinstance(time, pub.IntYamlTime)
        assert time.hour == 14
        assert time.minute == 38


class TestOldSchemaDatabase:
    def test_get_migrations_succeeds(self):
        migrations = self._get_migrations(
            3, ['03-to-02.sql', '02-to-01.sql', '01-to-00.sql']
        )

        # 01-to-00.sql should be skipped since 0 is invalid schema version
        assert len(migrations) == 2

        self._assert_migration(migrations[0], 3, 2)
        self._assert_migration(migrations[1], 2, 1)

    def _get_migrations(self, current_schema_version, script_file_names):
        with tempfile.TemporaryDirectory() as script_dir:
            self._create_empty_scripts(
                script_dir,
                script_file_names
            )

            return list(
                pub.OldSchemaDatabase.get_migrations(
                    current_schema_version, script_dir)
            )

    def _create_empty_scripts(self, script_dir, file_names):
        for file_name in file_names:
            self._create_empty_script(os.path.join(script_dir, file_name))

    def _create_empty_script(self, file_path):
        with open(file_path, mode='w'):
            pass

    def _assert_migration(self, migration, from_version, to_version):
        assert isinstance(migration, pub.Migration)
        assert migration.from_version == from_version
        assert migration.to_version == to_version


class TestPublisher:
    URL = 'http://example.com'
    UTF8_ENCODING = 'utf-8'
    VERSION = 'ab654321'
    SIGNATURE_HEADER = 'X-Content-Signature'

    def test_publishing_succeeds(self):
        httpretty.enable()
        httpretty.register_uri(httpretty.POST, self.URL, body='ok')

        pub.Publisher().publish(
            version=self.VERSION,
            databases=[
                StubDatabase(b'lorem', 1),
                StubDatabase(b'ipsum', 2)
            ],
            private_key_binary=KeyPair.PRIVATE,
            target_url=self.URL
        )

        body_binary = httpretty.last_request().body

        assert self._are_same_dicts(
            self._build_expected_body_dict(),
            json.loads(body_binary.decode(self.UTF8_ENCODING))
        )

        signature_binary = pub.Base64.base64_str_to_binary(
            httpretty.last_request().headers[self.SIGNATURE_HEADER]
        )
        assert SignatureVerifier.is_valid_signature(
            KeyPair.PUBLIC, body_binary, signature_binary
        )

    def _build_expected_body_dict(self):
        return dict(
            version=self.VERSION,
            schema_versions=[
                dict(
                    schema_version=1,
                    content='bG9yZW0='
                ),
                dict(
                    schema_version=2,
                    content='aXBzdW0='
                )
            ]
        )

    def _are_same_dicts(self, first, second):
        first_keys = set(first.keys())
        second_keys = set(second.keys())
        intersected_keys = first_keys.intersection(second_keys)

        if intersected_keys != first_keys:
            return False

        if intersected_keys != second_keys:
            return False

        for key in intersected_keys:
            if not self._are_same_dict_values(first[key], second[key]):
                return False

        return True

    def _are_same_dict_values(self, first, second):
        if isinstance(first, dict) and isinstance(second, dict):
            return self._are_same_dicts(first, second)
        elif isinstance(first, list) and isinstance(second, list):
            return self._are_same_lists(first, second)
        else:
            return first == second

    def _are_same_lists(self, first, second):
        if len(first) != len(second):
            return False

        for i in range(0, len(first)):
            if not self._are_same_dict_values(first[i], second[i]):
                return False

        return True


class StubDatabase(pub.Database):
    def __init__(self, content, schema_version):
        self._content = content
        self._schema_version = schema_version

    @property
    def content(self):
        return self._content

    @property
    def schema_version(self):
        return self._schema_version


class SignatureVerifier:
    @classmethod
    def is_valid_signature(cls, public_key_binary, message, signature):
        verifier = cls.build_signature_verifier(public_key_binary, signature)
        verifier.update(message)

        try:
            verifier.verify()
            return True
        except crypto_exceptions.InvalidSignature:
            return False

    @classmethod
    def build_signature_verifier(cls, public_key_binary, signature):
        public_key = crypto_serial.load_ssh_public_key(
            public_key_binary, crypto_backend()
        )
        return public_key.verifier(
            signature,
            crypto_padding.PKCS1v15(),
            crypto_hashes.SHA512()
        )


class KeyPair:
    PRIVATE = (
        b'\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x52\x53\x41\x20\x50'
        b'\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59\x2d\x2d\x2d\x2d\x2d\x0a'
        b'\x4d\x49\x49\x43\x58\x77\x49\x42\x41\x41\x4b\x42\x67\x51\x44\x71'
        b'\x69\x34\x79\x2b\x62\x6e\x76\x37\x6c\x62\x41\x36\x4a\x53\x72\x76'
        b'\x77\x30\x30\x4b\x4b\x5a\x6f\x6a\x64\x70\x43\x55\x37\x76\x59\x48'
        b'\x79\x4f\x4c\x63\x76\x6c\x6d\x78\x42\x4a\x52\x6d\x43\x59\x48\x6b'
        b'\x0a\x59\x7a\x35\x45\x66\x36\x6d\x74\x62\x36\x68\x5a\x75\x78\x66'
        b'\x71\x52\x6e\x32\x47\x67\x55\x6b\x4c\x75\x33\x52\x42\x57\x34\x62'
        b'\x68\x56\x4b\x52\x66\x47\x37\x79\x67\x67\x4b\x6f\x67\x5a\x61\x71'
        b'\x6d\x30\x51\x74\x67\x34\x69\x6e\x51\x6f\x56\x5a\x75\x2b\x65\x4e'
        b'\x30\x0a\x2b\x77\x65\x6b\x59\x4d\x6a\x5a\x43\x57\x30\x53\x54\x32'
        b'\x54\x66\x50\x77\x36\x59\x47\x30\x61\x5a\x76\x37\x30\x45\x32\x53'
        b'\x48\x38\x35\x6d\x32\x57\x63\x41\x42\x79\x34\x6f\x34\x4c\x72\x39'
        b'\x4b\x52\x30\x44\x53\x75\x2f\x6e\x4c\x31\x6b\x77\x49\x44\x41\x51'
        b'\x41\x42\x0a\x41\x6f\x47\x42\x41\x49\x51\x61\x33\x38\x59\x75\x30'
        b'\x72\x52\x73\x70\x6c\x72\x4a\x72\x6e\x70\x6e\x52\x56\x41\x78\x43'
        b'\x48\x6c\x72\x41\x5a\x70\x78\x55\x62\x41\x6d\x7a\x4f\x6a\x4b\x61'
        b'\x68\x68\x54\x58\x51\x5a\x76\x32\x6e\x4a\x36\x46\x34\x74\x62\x59'
        b'\x49\x57\x6f\x0a\x65\x32\x6b\x33\x41\x51\x78\x61\x63\x62\x38\x39'
        b'\x75\x4a\x66\x63\x47\x47\x6e\x72\x6c\x48\x66\x38\x52\x61\x75\x62'
        b'\x34\x78\x55\x62\x37\x39\x53\x35\x76\x64\x76\x6d\x44\x7a\x69\x34'
        b'\x51\x61\x61\x6a\x6c\x6c\x36\x4a\x68\x30\x51\x43\x6d\x53\x69\x53'
        b'\x34\x5a\x73\x44\x0a\x49\x55\x63\x44\x63\x6c\x76\x39\x63\x35\x5a'
        b'\x6f\x55\x68\x4c\x65\x44\x31\x38\x59\x57\x6a\x52\x75\x6e\x4e\x57'
        b'\x43\x38\x4c\x55\x78\x61\x54\x70\x75\x37\x5a\x36\x4e\x72\x6e\x4a'
        b'\x6f\x45\x4e\x52\x52\x41\x6b\x45\x41\x2f\x75\x5a\x4e\x72\x57\x74'
        b'\x34\x59\x53\x50\x56\x0a\x38\x64\x63\x47\x5a\x42\x4c\x73\x67\x6d'
        b'\x4f\x72\x2b\x62\x61\x71\x41\x71\x77\x50\x6e\x33\x44\x57\x30\x52'
        b'\x57\x52\x67\x54\x4c\x4b\x65\x51\x2b\x7a\x75\x79\x61\x41\x64\x42'
        b'\x46\x46\x6c\x39\x41\x71\x79\x70\x44\x61\x49\x46\x4b\x33\x55\x6b'
        b'\x6a\x6e\x53\x4e\x69\x57\x0a\x4c\x6d\x74\x4b\x30\x70\x74\x6f\x65'
        b'\x77\x4a\x42\x41\x4f\x75\x4f\x77\x49\x54\x2b\x75\x51\x6f\x70\x4d'
        b'\x56\x36\x44\x66\x47\x63\x49\x76\x6e\x51\x37\x44\x34\x4c\x45\x51'
        b'\x75\x70\x7a\x6b\x5a\x37\x49\x79\x48\x71\x75\x6f\x75\x61\x6a\x78'
        b'\x47\x78\x58\x43\x69\x2f\x64\x0a\x34\x77\x77\x64\x5a\x4d\x43\x62'
        b'\x54\x74\x48\x41\x4a\x64\x47\x43\x38\x50\x2b\x6e\x59\x58\x6b\x48'
        b'\x54\x56\x72\x47\x34\x78\x62\x61\x74\x38\x6b\x43\x51\x51\x43\x6b'
        b'\x54\x4d\x68\x32\x35\x74\x58\x79\x4c\x30\x6f\x68\x46\x30\x75\x4d'
        b'\x52\x39\x4a\x67\x2f\x57\x51\x46\x0a\x6b\x71\x4d\x6c\x45\x38\x6b'
        b'\x43\x4b\x5a\x61\x64\x73\x4c\x78\x59\x50\x65\x66\x61\x66\x71\x2b'
        b'\x49\x43\x33\x6f\x79\x31\x6b\x73\x34\x58\x72\x71\x6d\x56\x52\x58'
        b'\x30\x54\x62\x7a\x53\x63\x69\x46\x36\x68\x2f\x6a\x4e\x74\x4f\x54'
        b'\x47\x75\x64\x74\x76\x41\x6b\x45\x41\x0a\x78\x5a\x64\x6a\x53\x71'
        b'\x78\x5a\x44\x33\x72\x71\x58\x4c\x75\x79\x32\x4d\x4c\x75\x37\x35'
        b'\x53\x7a\x4f\x42\x2f\x6c\x65\x63\x45\x6a\x76\x36\x76\x77\x37\x32'
        b'\x67\x61\x59\x5a\x6d\x79\x4a\x4b\x63\x47\x64\x6f\x79\x4c\x37\x68'
        b'\x65\x68\x38\x69\x62\x56\x41\x51\x46\x4c\x0a\x4e\x2b\x6d\x38\x75'
        b'\x74\x62\x75\x33\x70\x55\x50\x67\x44\x77\x68\x4e\x59\x53\x57\x63'
        b'\x51\x4a\x42\x41\x4f\x65\x77\x57\x42\x75\x6f\x50\x65\x74\x67\x4c'
        b'\x35\x64\x2f\x51\x57\x6c\x35\x46\x4e\x76\x58\x61\x38\x79\x54\x37'
        b'\x53\x6e\x6c\x4c\x46\x34\x4a\x74\x76\x4e\x4c\x0a\x32\x73\x32\x2f'
        b'\x56\x7a\x68\x70\x77\x64\x39\x6e\x35\x69\x57\x36\x76\x57\x63\x56'
        b'\x6f\x50\x32\x77\x5a\x6d\x2f\x67\x70\x36\x72\x47\x6c\x38\x33\x43'
        b'\x56\x4e\x37\x36\x66\x6e\x79\x57\x30\x36\x67\x3d\x0a\x2d\x2d\x2d'
        b'\x2d\x2d\x45\x4e\x44\x20\x52\x53\x41\x20\x50\x52\x49\x56\x41\x54'
        b'\x45\x20\x4b\x45\x59\x2d\x2d\x2d\x2d\x2d\x0a'
    )

    PUBLIC = (
        b'\x73\x73\x68\x2d\x72\x73\x61\x20\x41\x41\x41\x41\x42\x33\x4e\x7a'
        b'\x61\x43\x31\x79\x63\x32\x45\x41\x41\x41\x41\x44\x41\x51\x41\x42'
        b'\x41\x41\x41\x41\x67\x51\x44\x71\x69\x34\x79\x2b\x62\x6e\x76\x37'
        b'\x6c\x62\x41\x36\x4a\x53\x72\x76\x77\x30\x30\x4b\x4b\x5a\x6f\x6a'
        b'\x64\x70\x43\x55\x37\x76\x59\x48\x79\x4f\x4c\x63\x76\x6c\x6d\x78'
        b'\x42\x4a\x52\x6d\x43\x59\x48\x6b\x59\x7a\x35\x45\x66\x36\x6d\x74'
        b'\x62\x36\x68\x5a\x75\x78\x66\x71\x52\x6e\x32\x47\x67\x55\x6b\x4c'
        b'\x75\x33\x52\x42\x57\x34\x62\x68\x56\x4b\x52\x66\x47\x37\x79\x67'
        b'\x67\x4b\x6f\x67\x5a\x61\x71\x6d\x30\x51\x74\x67\x34\x69\x6e\x51'
        b'\x6f\x56\x5a\x75\x2b\x65\x4e\x30\x2b\x77\x65\x6b\x59\x4d\x6a\x5a'
        b'\x43\x57\x30\x53\x54\x32\x54\x66\x50\x77\x36\x59\x47\x30\x61\x5a'
        b'\x76\x37\x30\x45\x32\x53\x48\x38\x35\x6d\x32\x57\x63\x41\x42\x79'
        b'\x34\x6f\x34\x4c\x72\x39\x4b\x52\x30\x44\x53\x75\x2f\x6e\x4c\x31'
        b'\x6b\x77\x3d\x3d\x20\x64\x6d\x69\x74\x72\x79\x2e\x61\x2e\x73\x61'
        b'\x76\x40\x67\x6d\x61\x69\x6c\x2e\x63\x6f\x6d\x0a'
    )


class TestBase64:
    def test_encode_succeeds(self):
        assert pub.Base64.binary_to_base64_str(b'1') == 'MQ=='

    def test_decode_succeeds(self):
        assert pub.Base64.base64_str_to_binary('MQ==') == b'1'

    def test_none_yields_empty(self):
        assert pub.Base64.binary_to_base64_str(None) is None
        assert pub.Base64.base64_str_to_binary(None) is None

    def test_empty_yields_empty(self):
        assert pub.Base64.binary_to_base64_str(b'') == ''
        assert pub.Base64.base64_str_to_binary('') == b''


class TestSignature:
    ENCODING = 'utf-8'

    def test_signing_succeeds(self):
        message = b'Lorem ipsum'
        signature = pub.Signature(KeyPair.PRIVATE).sign(message)
        assert SignatureVerifier.is_valid_signature(
            KeyPair.PUBLIC, message, signature
        )

    def test_invalid_signature_not_verifies(self):
        message = b'Lorem ipsum'
        signature = b'0' + pub.Signature(KeyPair.PRIVATE).sign(message)
        assert not SignatureVerifier.is_valid_signature(
            KeyPair.PUBLIC, message, signature
        )
