include toolchains/$(TOOLCHAIN).mk

stable:clean
	cd openusbtuner-driver && make
	cd openusbtuner-app && make
client: clean_client
	cd openusbtuner-app && make
clean:
	cd openusbtuner-driver && make clean
	cd openusbtuner-app && make clean
clean_client:
	cd openusbtuner-app && make clean