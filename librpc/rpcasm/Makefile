# make jkpatch

RPCLDR = rpcldr.bin
RPCSTUB = rpcstub.bin
RPCLDRS = rpcldr.s
RPCSTUBS = rpcstub.s

all: clean $(RPCLDR) $(RPCSTUB)

$(RPCLDR):
	nasm -f bin -o $(RPCLDR) $(RPCLDRS)

$(RPCSTUB):
	nasm -f bin -o $(RPCSTUB) $(RPCSTUBS)
	
.PHONY: clean
clean:
	rm -f $(RPCLDR) $(RPCSTUB)
