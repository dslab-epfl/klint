from collections.abc import Iterable

import datetime

_current_work: tuple[str, datetime.datetime] | None = None
_values: dict[str, float] = {}

def work_start(name: str) -> None:
    global _current_work
    assert _current_work is None
    _current_work = (name, datetime.datetime.now())

def work_end() -> None:
    global _current_work
    global _values
    assert _current_work is not None
    (name, start) = _current_work
    end = datetime.datetime.now()
    _values[name] = _values.get(name, 0) + (end - start).total_seconds()
    _current_work = None

def set_value(name: str, value: float) -> None:
    global _values
    _values[name] = value

def to_tsv() -> Iterable[str]:
    def to_str(value: float) -> str:
        if isinstance(value, float):
            return str(int(value))
        return str(value)

    global _values
    return [
        "\t".join(sorted(_values.keys())),
        "\t".join([to_str(_values[k]) for k in sorted(_values.keys())])
    ]
