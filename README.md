# Bus Time Publisher

A tool to publish Bus Time content to Bus Time backend server.

## Usage

Python 3.4 — 3.5 is required.

First, resolve dependencies:
```
$ pip install -r requirements.txt
```

Then create a configuration file from template:
```
$ cp config.ini.template config.ini
$ vi config.ini
```

Finally, run the publisher:
```
$ python publisher.py
```
