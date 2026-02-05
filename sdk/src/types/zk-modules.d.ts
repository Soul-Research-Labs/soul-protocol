// Type declarations for modules without types
declare module 'poseidon-lite' {
  export function poseidon1(inputs: bigint[]): bigint;
  export function poseidon2(inputs: bigint[]): bigint;
  export function poseidon3(inputs: bigint[]): bigint;
  export function poseidon4(inputs: bigint[]): bigint;
  export function poseidon5(inputs: bigint[]): bigint;
  export function poseidon6(inputs: bigint[]): bigint;
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
