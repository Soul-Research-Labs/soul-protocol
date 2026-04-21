.PHONY: up down deploy e2e logs

up:
	docker compose up -d
	@echo "waiting for anvil-l1..."
	@until curl -sf http://localhost:8545 > /dev/null; do sleep 1; done
	@echo "ready."

down:
	docker compose down -v

deploy: up
	CHAIN_ID=31337 RPC_URL=http://localhost:8545 \
	PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
	DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
	GOVERNOR_MULTISIG=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
	TIMELOCK_DELAY=60 \
	../../scripts/deploy.sh local

e2e: deploy
	cd ../.. && npx ts-node examples/e2e-local/scenario.ts

logs:
	docker compose logs -f --tail=200
