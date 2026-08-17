all:
	$(error please pick a target)

test:
	lein test

publish:
	@echo "Refusing local publish: push a v* release tag and let the guarded release workflow publish to Clojars." >&2; exit 1

.PHONY: all test publish
