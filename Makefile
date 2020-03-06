CC=gcc
CFLAGS=-W -Wall -pedantic 
LDFLAGS=
EXEC=elfdoctor

all: $(EXEC)

elfdoctor: elfdoctor.o
	@$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf *.o

mrproper: clean
	@rm -rf $(EXEC)
