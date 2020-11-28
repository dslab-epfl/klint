These files, except `main.c`, `spec.py`, and `Makefile`, come from the CRAB load balancer implementation.

They were modified to give up when there are IP options, since this is a pain to symbex and anyway Katran shows it's not realistic to support them.
See the "ADDED:" line in `common/parsing_helpers.h`
