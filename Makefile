CFLAGS = -std=c99 -Wall -static

ipvd: ipvd.c Makefile
	$(CC) $(CFLAGS) $< -o $@

sanity:
	@echo "Compiling with Clang..."; \
	clang -std=c99 -Wall -Weverything ipvd.c && rm a.out
	@echo "Compiling with GCC..."; \
	gcc -std=c99 -Wall -Wextra -pedantic ipvd.c && rm a.out

clean:
	rm -f ipvd

.PHONY: clean sanity
