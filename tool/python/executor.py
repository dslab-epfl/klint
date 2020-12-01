# Us
from . import symbex

def execute(solver, spec_text, spec_fun_name, spec_args, spec_external_names, spec_external_handler):
    state_box = [{}] # box it so we can pass the state around
    globals = {}
    for i, a in enumerate(spec_args):
        globals['__arg' + str(i)] = symbex.proxy(solver, a)
    for name in spec_external_names:
        def build_lambda(name):
            return lambda *args, **kwargs: spec_external_handler(name, state_box[0], *[symbex.unproxy(a) for a in args], **{symbex.unproxy(k): symbex.unproxy(v) for (k, v) in kwargs.items()})
        globals[name] = build_lambda(name)

    full_spec_text = spec_text + '\n\n\n' + spec_fun_name + '(' + ','.join(['__arg' + str(i) for (i, a) in enumerate(spec_args)]) + ')' + '\n'
    def run():
        state_box.clear()
        state_box.append({})
        exec(
            full_spec_text,
            # globals
            globals,
            # locals; have to be the same as globals, otherwise Python encapsulates the full_spec_text in a class and then one can't use classes inside it...
            globals
        )

    results = []
    def report(pathcond):
        results.append((pathcond, state_box[0]))

    symbex.symbex(run, report)
    return results
