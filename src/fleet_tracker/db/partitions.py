"""Pure calendar helpers used by partition maintenance and clock tests."""

from datetime import datetime, timezone

UTC = timezone.utc


def month_start(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def add_months(value: datetime, months: int) -> datetime:
    index = value.year * 12 + value.month - 1 + months
    year, month = divmod(index, 12)
    return value.replace(year=year, month=month + 1, day=1)


def partition_month_starts(*, now: datetime, months_ahead: int) -> tuple[datetime, ...]:
    start = month_start(now)
    return tuple(add_months(start, offset) for offset in range(months_ahead + 1))
