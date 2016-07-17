## Usage

Migration script from database schema `N` to database schema `N - 1` should
reside in a file `N-to-<N - 1>.sql`.

Such script should expect to find new schema file `N.db` in current
directory and should generate database of schema `N - 1` from contents
of this file.
