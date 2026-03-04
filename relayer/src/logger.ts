/**
 * ZASEON Relayer - Logger
 *
 * Structured JSON logging via pino.
 */

export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void;
  info(msg: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  warn(msg: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
  error(msg: string): void;
  debug(obj: Record<string, unknown>, msg?: string): void;
  debug(msg: string): void;
  fatal(obj: Record<string, unknown>, msg?: string): void;
  fatal(msg: string): void;
}

export function createLogger(component: string): Logger {
  const level = process.env.LOG_LEVEL || 'info';
  const levels: Record<string, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
  };
  const minLevel = levels[level] ?? 1;

  const log = (lvl: string, args: unknown[]) => {
    if ((levels[lvl] ?? 0) < minLevel) return;

    const entry: Record<string, unknown> = {
      level: lvl,
      component,
      time: new Date().toISOString(),
    };

    if (args.length === 1 && typeof args[0] === 'string') {
      entry.msg = args[0];
    } else if (args.length >= 1 && typeof args[0] === 'object' && args[0] !== null) {
      Object.assign(entry, args[0]);
      if (args.length > 1) entry.msg = args[1];
    }

    // eslint-disable-next-line no-console
    console.log(JSON.stringify(entry));
  };

  return {
    info: (...args: unknown[]) => log('info', args),
    warn: (...args: unknown[]) => log('warn', args),
    error: (...args: unknown[]) => log('error', args),
    debug: (...args: unknown[]) => log('debug', args),
    fatal: (...args: unknown[]) => log('fatal', args),
  } as Logger;
}
