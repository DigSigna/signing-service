from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import get_settings


def _build_database_url() -> str:
    settings = get_settings()
    settings.ensure_database_config()
    return settings.build_database_url()


def create_engine():
    settings = get_settings()
    kwargs = {
        "pool_pre_ping": True,
        # MySQL defaults to REPEATABLE READ, whose snapshot is fixed at a
        # transaction's first statement. This service shares its MySQL
        # schema with hsm-service and certificate-service (see
        # docker-compose.dev.yml): a read here can be followed by a call
        # out to one of those services (a separate connection on the same
        # database) that commits a row this session later needs to see
        # within the SAME transaction. Under REPEATABLE READ the old
        # snapshot can't see it even though it's already committed — READ
        # COMMITTED re-reads current data on every statement instead.
        "isolation_level": "READ COMMITTED",
    }
    if settings.mysql_ssl_required():
        kwargs["connect_args"] = {"ssl": {}}
    engine = create_async_engine(_build_database_url(), **kwargs)

    # asyncmy negotiates MySQL 8's modern default (utf8mb4_0900_ai_ci) for
    # the connection, but the shared schema's tables/columns are all
    # utf8mb4_unicode_ci. Local variables declared inside stored triggers
    # take the CONNECTION's collation, not the column's — mismatched, this
    # raises "Illegal mix of collations" the moment a trigger compares one
    # against a table column. Align the connection to the schema's collation.
    if engine.dialect.name == "mysql":

        @event.listens_for(engine.sync_engine, "connect")
        def _align_connection_collation(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci")
            cursor.close()

    return engine


_engine = create_engine()
AsyncSessionLocal = async_sessionmaker(_engine, expire_on_commit=False)


async def get_session():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    get_settings().ensure_database_config()
    async with _engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


async def ping_db() -> bool:
    try:
        get_settings().ensure_database_config()
        async with _engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def close_db() -> None:
    await _engine.dispose()
