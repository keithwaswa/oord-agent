.PHONY: test ctx ctx-full

test:
	@if command -v pytest >/dev/null 2>&1; then \
	  echo "[test] pytest"; \
	  PYTHONPATH=. pytest; \
	else \
	  echo "[test] (skipped pytest: pytest not installed)"; \
	fi

ctx:
	@bash scripts/ctx.sh

ctx-full:
	@DEPTH=3 LINES=800 bash scripts/ctx.sh
