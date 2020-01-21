LIB_EXAMPLE := lib/libexample.so

OBJS  := example.o

PROG_CFLAGS = $(CFLAGS) -fstrict-aliasing
PROG_LDFLAGS = $(LDFLAGS) -lbbfdm
FPIC := -fPIC

.PHONY: all

%.o: %.c
	$(CC) $(PROG_CFLAGS) $(FPIC) -c -o $@ $<

all: $(LIB_EXAMPLE)

$(LIB_EXAMPLE): $(OBJS)
	$(shell mkdir -p lib)
	$(CC) -shared -Wl,-soname,libexample.so $^ -o $@

clean:
	rm -f *.o
	rm -f $(LIB_EXAMPLE)

