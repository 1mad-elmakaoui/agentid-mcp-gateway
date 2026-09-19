# Migrations

The schema is currently created directly from the SQLAlchemy models:

```bash
agentid init          # Base.metadata.create_all
```

That is fine for development, the demo and the test suite, all of which start
from an empty database. It is **not** appropriate for a deployment that has data
to preserve.

## Adding Alembic

```bash
pip install alembic
alembic init agentid/database/migrations
```

Then point `env.py` at the metadata and the configured URL:

```python
from agentid.config import get_settings
from agentid.models import Base

target_metadata = Base.metadata
config.set_main_option("sqlalchemy.url", get_settings().database_url)
```

and generate the baseline from the current models:

```bash
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

## Things autogenerate will not get right

* **`EnumType` columns.** They render as `VARCHAR`, which is correct — the
  decorator only affects Python-side conversion — but a reviewer should confirm
  the lengths.
* **`audit_events` is append-only by convention, not by constraint.** If you
  want that enforced, add a database rule or a restricted role; no migration
  will infer it.
* **Index choices.** The models index the columns the audit API filters on
  (`timestamp`, `tool`, `decision`, `user_id`, `agent_id`, `request_id`). Review
  them against your real query patterns before the table grows.
