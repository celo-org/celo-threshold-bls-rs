-include .env

build:
	cargo build --profile release

deploy:
	./target/release/dkg-cli deploy -n $(NODE_URL) -p $(PRIVATE_KEY) -t $(THRESHOLD) -P $(PHASE_DURATION)

allow-self:
	./target/release/dkg-cli allow -n $(NODE_URL) -p $(PRIVATE_KEY) -c $(CONTRACT_ADDRESS) -a $(SELF_ADDRESS)

run:
	./target/release/dkg-cli run -n $(NODE_URL) -p $(PRIVATE_KEY) -c $(CONTRACT_ADDRESS) -o dkg-output

start:
	./target/release/dkg-cli start -n $(NODE_URL) -p $(PRIVATE_KEY) -c $(CONTRACT_ADDRESS)

image:
	docker build -t dkg-cli -f crates/dkg-cli/Dockerfile .
