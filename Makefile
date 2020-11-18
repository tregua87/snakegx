APP_MK:=app.mk

.PHONY: all
all:
	$(MAKE) -C $(shell dirname $(APP_MK)) -f $(shell basename $(APP_MK)) $@
