# make jkpatch

TARGET = payload.bin
KTARGET = kpayload.elf

all: clean $(TARGET) $(KTARGET)

$(TARGET):
	cd payload && $(MAKE) -s
	cp payload/$(TARGET) $(TARGET)

$(KTARGET):
	cd kpayload && $(MAKE) -s
	cp kpayload/$(KTARGET) $(KTARGET)
	elfedit --output-type=DYN $(KTARGET)
	
.PHONY: clean
clean:
	rm -f $(TARGET) $(KTARGET)
	cd payload && $(MAKE) -s clean
	cd kpayload && $(MAKE) -s clean
