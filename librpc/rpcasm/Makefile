# make jkpatch

RPCSTUB = rpcstub.bin
RPCSTUBS = rpcstub.s

all: clean $(RPCSTUB)

$(RPCSTUB):
	nasm -f bin -o $(RPCSTUB) $(RPCSTUBS)
	
.PHONY: clean
clean:
	rm -f $(RPCSTUB)
