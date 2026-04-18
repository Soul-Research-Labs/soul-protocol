/**
 * WorkerPool — bounded pool of Web Workers / Node worker_threads for proof
 * generation. The SDK hands off heavy `generateProof(witness)` work so the
 * calling thread stays responsive and N proofs can be generated in parallel.
 *
 * Runtime-agnostic: uses globalThis.Worker when present (browsers) and the
 * `worker_threads` module when not (Node). Callers provide the worker
 * script URL/path at construction time.
 */
export interface WorkerHandle {
  postMessage(msg: unknown, transfer?: unknown[]): void;
  terminate(): Promise<number> | void;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}

export interface WorkerFactory {
  create(): WorkerHandle;
}

interface PendingJob {
  id: number;
  payload: unknown;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

export interface WorkerPoolOptions {
  /** Max concurrent workers. Defaults to `min(cpu, 4)`. */
  maxWorkers?: number;
  /** Per-job timeout ms. Default 30 s. */
  timeoutMs?: number;
}

/**
 * Pool of workers with a FIFO job queue. `submit(payload)` returns a promise
 * resolved with whatever the worker posts back via `postMessage`. Workers
 * must echo `{ id, result }` or `{ id, error }`.
 */
export class WorkerPool {
  private factory: WorkerFactory;
  private maxWorkers: number;
  private timeoutMs: number;
  private idle: WorkerHandle[] = [];
  private busy = new Map<WorkerHandle, PendingJob>();
  private queue: PendingJob[] = [];
  private nextId = 1;
  private closed = false;

  constructor(factory: WorkerFactory, opts: WorkerPoolOptions = {}) {
    this.factory = factory;
    this.maxWorkers = Math.max(1, opts.maxWorkers ?? 4);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  get active(): number {
    return this.busy.size + this.idle.length;
  }

  submit<TOut = unknown>(payload: unknown): Promise<TOut> {
    if (this.closed) return Promise.reject(new Error("WorkerPool closed"));
    return new Promise<TOut>((resolve, reject) => {
      const job: PendingJob = {
        id: this.nextId++,
        payload,
        resolve: resolve as (v: unknown) => void,
        reject,
      };
      this.queue.push(job);
      this._drain();
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const w of [...this.idle, ...this.busy.keys()]) {
      const r = w.terminate();
      if (r && typeof (r as Promise<number>).then === "function") await r;
    }
    this.idle = [];
    this.busy.clear();
  }

  private _drain(): void {
    while (this.queue.length > 0) {
      let worker = this.idle.pop();
      if (!worker) {
        if (this.active >= this.maxWorkers) return;
        worker = this.factory.create();
      }
      const job = this.queue.shift()!;
      this._dispatch(worker, job);
    }
  }

  private _dispatch(worker: WorkerHandle, job: PendingJob): void {
    this.busy.set(worker, job);
    const timer = setTimeout(() => {
      this.busy.delete(worker);
      worker.terminate();
      job.reject(new Error(`WorkerPool job ${job.id} timed out`));
      this._drain();
    }, this.timeoutMs);

    worker.onmessage = (ev) => {
      const msg = ev.data as { id: number; result?: unknown; error?: string };
      if (!msg || msg.id !== job.id) return;
      clearTimeout(timer);
      this.busy.delete(worker);
      if (msg.error) job.reject(new Error(msg.error));
      else job.resolve(msg.result);
      if (!this.closed) this.idle.push(worker);
      this._drain();
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      this.busy.delete(worker);
      worker.terminate();
      job.reject(err instanceof Error ? err : new Error(String(err)));
      this._drain();
    };

    worker.postMessage({ id: job.id, payload: job.payload });
  }
}
