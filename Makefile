ROOT_DIR=$(shell pwd)/
TESTDIR=$(ROOT_DIR)/tests
PHPS=php -S 127.0.0.1:5000
PHPUNIT=vendor/bin/phpunit
INFECTION_VERSION=0.15.3
INFECTION_ARGS=

all: install clean tests

install:
	composer update

tests: test-server run-phpunit psalm run-infection kill-test-server

coverage: PUARGS="--coverage-clover=coverage.xml"
coverage: tests-unit

tests-unit: test-server run-phpunit kill-test-server

run-phpunit:
	@$(PHPUNIT) $(PUARGS)

psalm:
	vendor/bin/psalm

psalm-ci:
	vendor/bin/psalm --shepherd

test-server:
	@echo -n "Starting embedded server"
	$(eval SRV_PID=$(shell $(PHPS) $(TESTDIR)/server.php > /dev/null & echo $$!))
	@echo " (PID $(SRV_PID))"

kill-test-server:
	kill -SIGINT $(SRV_PID)

infection.phar:
	wget --no-check-certificate "https://github.com/infection/infection/releases/download/$(INFECTION_VERSION)/infection.phar"
	wget --no-check-certificate "https://github.com/infection/infection/releases/download/$(INFECTION_VERSION)/infection.phar.asc"
	chmod +x infection.phar

infection: infection.phar test-server run-infection kill-test-server

infection-ci: INFECTION_ARGS=--logger-github --git-diff-filter=AM
infection-ci: INFECTION_VERSION=0.23.0
infection-ci: infection

run-infection: infection.phar
	./infection.phar $(INFECTION_ARGS)

clean:
	rm -f /tmp/test-db.sqlite

.PHONY: tests test-server clean install infection infection-ci psalm psalm-ci
