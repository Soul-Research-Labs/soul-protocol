/**
 * Zaseon SDK Retry Utility
 * 
 * Exponential backoff retry logic with configurable options,
 * jitter, and error classification.
 */

import {
  ZaseonError,
  NetworkError,
  TimeoutError,
  isZaseonError,
} from "./errors";

/**
 * Retry configuration options
 */
export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxAttempts?: number;
  /** Initial delay in milliseconds (default: 1000) */
  initialDelayMs?: number;
  /** Maximum delay in milliseconds (default: 30000) */
  maxDelayMs?: number;
  /** Exponential backoff factor (default: 2) */
  backoffFactor?: number;
  /** Add random jitter to delay (default: true) */
  jitter?: boolean;
  /** Jitter factor 0-1 (default: 0.1) */
  jitterFactor?: number;
  /** Custom retry condition */
  shouldRetry?: (error: Error, attempt: number) => boolean;
  /** Callback on each retry */
  onRetry?: (error: Error, attempt: number, delayMs: number) => void;
  /** Timeout per attempt in milliseconds */
  timeoutMs?: number;
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}

/**
 * Default retry options
 */
const DEFAULT_OPTIONS: Required<Omit<RetryOptions, "shouldRetry" | "onRetry" | "timeoutMs" | "signal">> = {
  maxAttempts: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffFactor: 2,
  jitter: true,
  jitterFactor: 0.1,
};

/**
 * Calculate delay for attempt with exponential backoff and jitter
 */
function calculateDelay(
  attempt: number,
  options: Required<Omit<RetryOptions, "shouldRetry" | "onRetry" | "timeoutMs" | "signal">>
): number {
  // Exponential backoff
  let delay = options.initialDelayMs * Math.pow(options.backoffFactor, attempt - 1);
  
  // Cap at max delay
  delay = Math.min(delay, options.maxDelayMs);
  
  // Add jitter
  if (options.jitter) {
    const jitterRange = delay * options.jitterFactor;
    // Note: Math.random() is used intentionally here for non-security-critical timing jitter.
    // Cryptographic randomness is not required for retry delay jitter.
    const jitter = (Math.random() * 2 - 1) * jitterRange;
    delay = Math.max(0, delay + jitter);
  }
  
  return Math.floor(delay);
}

/**
 * Default retry condition - retry on network and timeout errors
 */
function defaultShouldRetry(error: Error, _attempt: number): boolean {
  // Always retry network errors
  if (error instanceof NetworkError) {
    return true;
  }
  
  // Retry timeout errors
  if (error instanceof TimeoutError) {
    return true;
  }
  
  // Check if error is marked as retryable
  if (isZaseonError(error)) {
    return error.retryable;
  }
  
  // Check for common transient error patterns
  const message = error.message.toLowerCase();
  const transientPatterns = [
    "timeout",
    "etimedout",
    "econnreset",
    "econnrefused",
    "enotfound",
    "socket hang up",
    "network",
    "rate limit",
    "too many requests",
    "503",
    "502",
    "504",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
  ];
  
  return transientPatterns.some(pattern => message.includes(pattern));
}

/**
 * Sleep for a given duration
 */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Aborted"));
      return;
    }
    
    const timeout = setTimeout(resolve, ms);
    
    if (signal) {
      signal.addEventListener("abort", () => {
        clearTimeout(timeout);
        reject(new Error("Aborted"));
      }, { once: true });
    }
  });
}

/**
 * Wrap a function with timeout
 */
async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new TimeoutError(operation, timeoutMs));
    }, timeoutMs);
    
    fn()
      .then(result => {
        clearTimeout(timeoutId);
        resolve(result);
      })
      .catch(error => {
        clearTimeout(timeoutId);
        reject(error);
      });
  });
}

/**
 * Retry a function with exponential backoff
 * 
 * @example
 * ```typescript
 * const result = await retry(
 *   async () => await contractCall(),
 *   { maxAttempts: 5, initialDelayMs: 500 }
 * );
 * ```
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const shouldRetry = options.shouldRetry || defaultShouldRetry;
  
  let lastError: Error | undefined;
  
  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      // Check for abort
      if (options.signal?.aborted) {
        throw new Error("Operation aborted");
      }
      
      // Execute with optional timeout
      const result = options.timeoutMs
        ? await withTimeout(fn, options.timeoutMs, "operation")
        : await fn();
      
      return result;
    } catch (error) {
      lastError = error as Error;
      
      // Check if we should retry
      const isLastAttempt = attempt === opts.maxAttempts;
      
      if (isLastAttempt || !shouldRetry(lastError, attempt)) {
        throw lastError;
      }
      
      // Calculate delay
      const delay = calculateDelay(attempt, opts);
      
      // Call retry callback
      options.onRetry?.(lastError, attempt, delay);
      
      // Wait before retry
      await sleep(delay, options.signal);
    }
  }
  
  // Should never reach here, but TypeScript needs it
  throw lastError;
}

/**
 * Retry decorator for class methods
 */
export function Retryable(options: RetryOptions = {}) {
  return function (
    _target: unknown,
    _propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: unknown[]) {
      return retry(() => originalMethod.apply(this, args), options);
    };
    
    return descriptor;
  };
}

/**
 * Create a retryable version of a function
 */
export function retryable<T extends (...args: unknown[]) => Promise<unknown>>(
  fn: T,
  options: RetryOptions = {}
): T {
  return (async (...args: Parameters<T>) => {
    return retry(() => fn(...args), options);
  }) as T;
}

/**
 * Retry with circuit breaker pattern
 */
export interface CircuitBreakerOptions extends RetryOptions {
  /** Number of failures before opening circuit (default: 5) */
  failureThreshold?: number;
  /** Time to wait before trying again when circuit is open (default: 60000) */
  resetTimeoutMs?: number;
}

export class CircuitBreaker<T> {
  private failures = 0;
  private lastFailureTime = 0;
  private state: "closed" | "open" | "half-open" = "closed";
  
  constructor(
    private readonly fn: () => Promise<T>,
    private readonly options: CircuitBreakerOptions = {}
  ) {}
  
  async call(): Promise<T> {
    const failureThreshold = this.options.failureThreshold ?? 5;
    const resetTimeoutMs = this.options.resetTimeoutMs ?? 60000;
    
    // Check circuit state
    if (this.state === "open") {
      if (Date.now() - this.lastFailureTime >= resetTimeoutMs) {
        this.state = "half-open";
      } else {
        throw new NetworkError("Circuit breaker is open", {
          statusCode: 503,
        });
      }
    }
    
    try {
      const result = await retry(this.fn, this.options);
      
      // Success - close circuit
      this.failures = 0;
      this.state = "closed";
      
      return result;
    } catch (error) {
      this.failures++;
      this.lastFailureTime = Date.now();
      
      if (this.failures >= failureThreshold) {
        this.state = "open";
      }
      
      throw error;
    }
  }
  
  reset(): void {
    this.failures = 0;
    this.state = "closed";
  }
  
  getState(): "closed" | "open" | "half-open" {
    return this.state;
  }
}

/**
 * Batch retry - retry multiple operations together
 */
export async function retryAll<T>(
  operations: Array<() => Promise<T>>,
  options: RetryOptions = {}
): Promise<T[]> {
  return retry(
    () => Promise.all(operations.map(op => op())),
    options
  );
}

/**
 * Retry with fallback
 */
export async function retryWithFallback<T>(
  primary: () => Promise<T>,
  fallback: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  try {
    return await retry(primary, options);
  } catch {
    // Primary exhausted retries, try fallback
    return await retry(fallback, options);
  }
}
