CC = g++
LDLIBS = -lpcap

all: deauth-attack

deauth-attack: main.o mac.o send_deauth.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	@rm -f ./deauth-atack *.o
