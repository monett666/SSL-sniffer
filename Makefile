CC = g++
CFLAGS = -I -g -lpcap -std=c++11
OBJ = main.o args.o
NAME = sslsniff

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.cpp %.hpp
	$(CC) -c $< $(CFLAGS)

pack:
	tar -czvf xbures32.tar *.cpp *.hpp Makefile

zip:
	zip xbures32.zip *.cpp *.hpp Makefile

clean:
	rm -rf *.o *.out $(NAME)