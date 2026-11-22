# SeaORM 2.0.4 patch

The vault pins this local SeaORM release for two compatibility changes.

- Remove weak Arrow feature forwarding from `with-time` and weak Chrono serde forwarding from `with-json`. Cargo otherwise resolves both optional dependencies into the lockfile, and Arrow also brings in Chrono.
- Bind primitive timestamps using the historical text format in the SQLite driver. Whole seconds omit the fractional part. Nonzero fractions use three, six, or nine digits. Keeping that representation preserves indexed equality and pagination boundaries in existing databases.

The patch also gates a SQLite import on its corresponding feature to keep builds warning-free.

The upstream library sources are distributed under the included MIT and Apache licenses.
