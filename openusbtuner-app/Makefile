all:
	$(GCC) -o $(PWD)/../build/$(BOX)/usbotunerhelper -pthread -I../openusbtuner-driver -Wall -DINSIDE_USER_SPACE usbotunerhelper.c ../openusbtuner-driver/logs.c

clean:
	rm -f $(PWD)/../build/$(BOX)/usbotunerhelper

