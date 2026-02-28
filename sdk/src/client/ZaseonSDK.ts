import {
  CryptoModule,
  ZaseonConfig,
  SendParams,
  Receipt,
  CircuitInputs,
  CircuitWitnesses,
} from "../utils/crypto";
import {
  ZaseonError,
  ZaseonErrorCode,
  withRetry,
  withTimeout,
  withRetryAndTimeout,
  RetryOptions,
} from "../utils/errors";

/** Proof generation result */
export interface ProofResult {
  proof: Buffer;
  publicInputs: Buffer;
}

/** Packet structure for relayer communication */
export interface RelayerPacket {
  encryptedState: Buffer;
  ephemeralKey: Buffer;
  mac: Buffer;
  proof: ProofResult;
  sourceChain: string;
  destChain: string;
  timestamp: number;
}

/** Subscription handle for cleanup */
export interface Subscription {
  unsubscribe: () => void;
}

/** Proof generation parameters */
export interface ProofParams {
  circuit: string;
  inputs?: CircuitInputs;
  witnesses?: CircuitWitnesses;
}

export class ProverModule {
  constructor(public proverUrl: string) {}

  /**
   * Generate a ZK proof for the given circuit and inputs.
   * Includes automatic retry with exponential backoff for network failures.
   * @param params - Circuit identifier and witness inputs
   * @param retryOptions - Optional retry configuration
   * @returns Proof and public inputs
   * @throws ZaseonError on failure after retries
   */
  async generateProof(
    params: ProofParams,
    retryOptions?: RetryOptions,
  ): Promise<ProofResult> {
    return withRetryAndTimeout(
      async () => {
        if (!params.circuit) {
          throw new ZaseonError(
            "Circuit identifier is required",
            ZaseonErrorCode.INVALID_INPUT,
            { context: { params } },
          );
        }

        // Remote prover service via HTTP POST
        const res = await fetch(`${this.proverUrl}/prove`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            circuit: params.circuit,
            inputs: params.inputs,
            witnesses: params.witnesses,
          }),
        });

        if (!res.ok) {
          const body = await res.text().catch(() => "unknown");
          throw new ZaseonError(
            `Prover service returned ${res.status}: ${body}`,
            ZaseonErrorCode.PROOF_GENERATION_FAILED,
            { context: { status: res.status } },
          );
        }

        const data = await res.json();
        return {
          proof: Buffer.from(data.proof, "hex"),
          publicInputs: Buffer.from(data.publicInputs, "hex"),
        };
      },
      {
        timeoutMs: 60000, // 60 second timeout for proof generation
        operation: "proof generation",
        maxAttempts: 2, // Only retry once for proof generation
        ...retryOptions,
        onRetry: (error, attempt, delay) => {
          console.warn(
            `Proof generation failed (attempt ${attempt}), retrying in ${delay}ms:`,
            error.message,
          );
          retryOptions?.onRetry?.(error, attempt, delay);
        },
      },
    );
  }

  /**
   * Verify a ZK proof against the given state root.
   * @param proof - The proof to verify
   * @param stateRoot - Expected state root
   * @returns True if proof is valid
   * @throws ZaseonError if verification fails
   */
  async verifyProof(proof: ProofResult, stateRoot: string): Promise<boolean> {
    return withTimeout(
      async () => {
        if (!proof.proof || proof.proof.length === 0) {
          throw new ZaseonError(
            "Invalid proof: empty proof buffer",
            ZaseonErrorCode.INVALID_PROOF,
          );
        }

        const res = await fetch(`${this.proverUrl}/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            proof: Buffer.from(proof.proof).toString("hex"),
            publicInputs: Buffer.from(proof.publicInputs).toString("hex"),
            stateRoot,
          }),
        });

        if (!res.ok) {
          throw new ZaseonError(
            `Verification service returned ${res.status}`,
            ZaseonErrorCode.INVALID_PROOF,
          );
        }

        const data = await res.json();
        return data.valid === true;
      },
      10000, // 10 second timeout for verification
      "proof verification",
    );
  }
}

/** Relayer send options */
export interface RelayerOptions {
  mixnet: boolean;
  decoyTraffic: boolean;
  maxDelay: number;
}

export class RelayerClient {
  constructor(public endpoint: string) {}

  /**
   * Send an encrypted packet through the relayer network.
   * Includes automatic retry with exponential backoff for network failures.
   * @param packet - Encrypted state packet
   * @param opts - Relay options (mixnet, decoy traffic)
   * @param retryOptions - Optional retry configuration
   * @returns Transaction receipt
   * @throws ZaseonError on failure after retries
   */
  async send(
    packet: RelayerPacket,
    opts: RelayerOptions,
    retryOptions?: RetryOptions,
  ): Promise<Receipt> {
    return withRetryAndTimeout(
      async () => {
        // Validate packet
        if (!packet.encryptedState || packet.encryptedState.length === 0) {
          throw new ZaseonError(
            "Invalid packet: empty encrypted state",
            ZaseonErrorCode.INVALID_INPUT,
          );
        }
        if (!packet.destChain) {
          throw new ZaseonError(
            "Invalid packet: destination chain is required",
            ZaseonErrorCode.INVALID_INPUT,
          );
        }

        const res = await fetch(`${this.endpoint}/relay`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            encryptedState: packet.encryptedState.toString("hex"),
            ephemeralKey: packet.ephemeralKey.toString("hex"),
            mac: packet.mac.toString("hex"),
            proof: {
              proof: Buffer.from(packet.proof.proof).toString("hex"),
              publicInputs: Buffer.from(packet.proof.publicInputs).toString(
                "hex",
              ),
            },
            sourceChain: packet.sourceChain,
            destChain: packet.destChain,
            timestamp: packet.timestamp,
            options: {
              mixnet: opts.mixnet,
              decoyTraffic: opts.decoyTraffic,
              maxDelay: opts.maxDelay,
            },
          }),
        });

        if (!res.ok) {
          const body = await res.text().catch(() => "unknown");
          throw new ZaseonError(
            `Relayer returned ${res.status}: ${body}`,
            ZaseonErrorCode.RELAY_FAILED,
          );
        }

        const data = await res.json();
        return { txHash: data.txHash, status: data.status ?? "sent" };
      },
      {
        timeoutMs: 30000, // 30 second timeout for relay
        operation: "relayer send",
        maxAttempts: 3,
        ...retryOptions,
        onRetry: (error, attempt, delay) => {
          console.warn(
            `Relay failed (attempt ${attempt}), retrying in ${delay}ms:`,
            error.message,
          );
          retryOptions?.onRetry?.(error, attempt, delay);
        },
      },
    );
  }

  /**
   * Subscribe to incoming packets on a chain.
   * @param chainId - Chain to subscribe to
   * @param callback - Handler for incoming packets
   * @returns Subscription handle
   */
  async subscribe(
    chainId: string,
    callback: (packet: RelayerPacket) => void,
  ): Promise<Subscription> {
    if (!chainId) {
      throw new ZaseonError(
        "Chain ID is required for subscription",
        ZaseonErrorCode.INVALID_INPUT,
      );
    }

    // Subscribe via WebSocket for real-time packet delivery
    const wsUrl =
      this.endpoint.replace(/^http/, "ws") + `/subscribe/${chainId}`;
    let ws: WebSocket | null = null;

    try {
      ws = new WebSocket(wsUrl);

      ws.onmessage = (event: MessageEvent) => {
        try {
          const raw = JSON.parse(String(event.data));
          const packet: RelayerPacket = {
            encryptedState: Buffer.from(raw.encryptedState, "hex"),
            ephemeralKey: Buffer.from(raw.ephemeralKey, "hex"),
            mac: Buffer.from(raw.mac, "hex"),
            proof: {
              proof: Buffer.from(raw.proof.proof, "hex"),
              publicInputs: Buffer.from(raw.proof.publicInputs, "hex"),
            },
            sourceChain: raw.sourceChain,
            destChain: raw.destChain,
            timestamp: raw.timestamp,
          };
          callback(packet);
        } catch {
          // Skip malformed messages
        }
      };

      ws.onerror = () => {
        console.warn("Relayer WebSocket error");
      };
    } catch {
      console.warn("WebSocket connection failed for relayer subscription");
    }

    return {
      unsubscribe: () => {
        if (ws) {
          ws.close();
          ws = null;
        }
      },
    };
  }
}

/** Decrypted state callback */
export type StateCallback = (state: Buffer) => void;

export class ZaseonSDK {
  private crypto: CryptoModule;
  private relayer: RelayerClient;
  private prover: ProverModule;

  constructor(private config: ZaseonConfig) {
    this.crypto = new CryptoModule(config.curve);
    this.relayer = new RelayerClient(config.relayerEndpoint);
    this.prover = new ProverModule(config.proverUrl);
  }

  async sendPrivateState(params: SendParams): Promise<Receipt> {
    // 1. Serialize and encrypt state
    const serializedState = Buffer.from(JSON.stringify(params.payload));
    const { ciphertext, ephemeralKey, mac } = await this.crypto.encrypt(
      serializedState,
      params.destChain,
    );

    // 2. Generate validity proof
    const proof = await this.prover.generateProof({
      circuit: params.circuitId,
      inputs: params.inputs,
      witnesses: params.witnesses,
    });

    // 3. Package and send via relayer
    const packet: RelayerPacket = {
      encryptedState: ciphertext,
      ephemeralKey,
      mac,
      proof,
      sourceChain: params.sourceChain,
      destChain: params.destChain,
      timestamp: Date.now(),
    };
    return this.relayer.send(packet, {
      mixnet: true,
      decoyTraffic: true,
      maxDelay: params.maxDelay || 30000,
    });
  }

  async receivePrivateState(
    chainId: string,
    callback: StateCallback,
  ): Promise<Subscription> {
    return this.relayer.subscribe(chainId, async (packet: RelayerPacket) => {
      // Decrypt with ECIES using receiver's private key
      let decrypted: Buffer;
      try {
        const privateKeyBuf = Buffer.from(
          this.config.privateKey.replace(/^0x/, ""),
          "hex",
        );
        decrypted = await this.crypto.decrypt(
          packet.encryptedState,
          packet.ephemeralKey,
          packet.mac,
          privateKeyBuf,
        );
      } catch (e: unknown) {
        console.error(
          `Decryption failed: ${e instanceof Error ? e.message : String(e)}`,
        );
        return; // Skip this packet — cannot decrypt
      }

      const isValid = await this.prover.verifyProof(packet.proof, "stateRoot");
      if (isValid) {
        callback(decrypted);
      }
    });
  }
}
