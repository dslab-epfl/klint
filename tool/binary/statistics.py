import datetime

# TODO this is not the right place for this

_current_work = None
_values = {}

def work_start(name):
    global _current_work
    assert _current_work is None
    _current_work = (name, datetime.datetime.now())

def work_end():
    global _current_work
    global _values
    assert _current_work is not None
    (name, start) = _current_work
    end = datetime.datetime.now()
    _values[name] = _values.get(name, 0) + (end - start).total_seconds()
    _current_work = None

def set_value(name, value):
    global _values
    _values[name] = value

def to_tsv():
    def to_str(value):
        if isinstance(value, float):
            return str(int(value))
        return str(value)

    global _values
    return [
        "\t".join(sorted(_values.keys())),
        "\t".join([to_str(_values[k]) for k in sorted(_values.keys())])
    ]
