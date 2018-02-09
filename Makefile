# make jkpatch

TARGET = payload.bin
KTARGET = kpayload.elf

all: $(TARGET) $(KTARGET)

$(TARGET):
	cd payload && $(MAKE) -s
	cp payload/$(TARGET) $(TARGET)

$(KTARGET):
	cd kpayload && $(MAKE) -s
	cp kpayload/$(KTARGET) $(KTARGET)
	
.PHONY: clean
clean:
	rm $(TARGET) $(KTARGET)
	cd payload && $(MAKE) -s clean
	cd kpayload && $(MAKE) -s clean
