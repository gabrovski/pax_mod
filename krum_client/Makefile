obj-m := krum_client.o
KDIR := /lib/modules/3.2.11-pax/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules