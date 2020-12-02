def execute(spec_text, spec_fun_name, spec_args, spec_external_names, spec_external_handler):
    globals = {}
    for i, a in enumerate(spec_args):
        globals['__arg' + str(i)] = a
    for name in spec_external_names:
        def build_lambda(name):
            return lambda *args, **kwargs: spec_external_handler(name, *args, **kwargs)
        globals[name] = build_lambda(name)

    full_spec_text = spec_text + '\n\n\n' + spec_fun_name + '(' + ','.join(['__arg' + str(i) for (i, a) in enumerate(spec_args)]) + ')' + '\n'

    exec(
        full_spec_text,
        # globals
        globals,
        # locals; have to be the same as globals, otherwise Python encapsulates the full_spec_text in a class and then one can't use classes inside it...
        globals
    )
