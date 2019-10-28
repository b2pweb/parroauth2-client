ROOT_DIR=$(shell pwd)/
TESTDIR=$(ROOT_DIR)/tests
PHPS=php -S 127.0.0.1:5000
PHPUNIT=vendor/bin/phpunit

all: install clean tests

install:
	composer update

tests: test-server
	@$(PHPUNIT) $(PUARGS)
	kill -SIGINT $(SRV_PID)

test-server:
	@echo -n "Starting embedded server"
	$(eval SRV_PID=$(shell $(PHPS) $(TESTDIR)/server.php > /dev/null & echo $$!))
	@echo " (PID $(SRV_PID))"

clean:
	rm -f /tmp/test-db.sqlite

.PHONY: tests tests-server clean install
