// Type declarations for modules without types
declare module 'circomlibjs' {
  export function buildPoseidon(): Promise<{
    (...inputs: (bigint | number | string | Uint8Array)[]): Uint8Array;
    F: object;
  }>;
  
  export function buildEddsa(): Promise<{
    prv2pub(privateKey: Uint8Array): [Uint8Array, Uint8Array];
    signPoseidon(privateKey: Uint8Array, msg: bigint): {
      R8: [bigint, bigint];
      S: bigint;
    };
    verifyPoseidon(msg: bigint, signature: { R8: [bigint, bigint]; S: bigint }, pubKey: [Uint8Array, Uint8Array]): boolean;
  }>;
  
  export function buildBabyjub(): Promise<{
    addPoint(p1: [bigint, bigint], p2: [bigint, bigint]): [bigint, bigint];
    mulPointEscalar(p: [bigint, bigint], s: bigint): [bigint, bigint];
    inCurve(p: [bigint, bigint]): boolean;
    packPoint(p: [bigint, bigint]): Uint8Array;
    unpackPoint(buf: Uint8Array): [bigint, bigint];
    Base8: [bigint, bigint];
    p: bigint;
    order: bigint;
  }>;
  
  export function buildMimc7(): Promise<{
    hash(left: bigint, right: bigint): bigint;
    multiHash(arr: bigint[]): bigint;
  }>;
  
  export function buildMimcsponge(): Promise<{
    hash(left: bigint, right: bigint, k: bigint): bigint;
    multiHash(arr: bigint[], k: bigint, numOutputs: number): bigint[];
  }>;
}

declare module 'snarkjs' {
  export namespace groth16 {
    export function fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    
    export function verify(
      vkey: unknown,
      publicSignals: string[],
      proof: unknown
    ): Promise<boolean>;
    
    export function exportSolidityCallData(
      proof: unknown,
      publicSignals: string[]
    ): Promise<string>;
  }
  
  export namespace plonk {
    export function fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    
    export function verify(
      vkey: unknown,
      publicSignals: string[],
      proof: unknown
    ): Promise<boolean>;
  }
  
  export namespace zKey {
    export function exportVerificationKey(zkeyFile: string): Promise<unknown>;
  }
}
