# make jkpatch

RPCSTUB = rpcstub.bin
RPCSTUBS = rpcstub.s
RPCLDR = rpcldr.bin
RPCLDRS = rpcldr.s

all: clean $(RPCSTUB) $(RPCLDR)

$(RPCSTUB):
	nasm -f bin -o $(RPCSTUB) $(RPCSTUBS)
	nasm -f bin -o $(RPCLDR) $(RPCLDRS)
	
.PHONY: clean
clean:
	rm -f $(RPCSTUB) $(RPCLDR)
