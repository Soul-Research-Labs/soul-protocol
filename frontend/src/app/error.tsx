'use client';

import { useEffect } from 'react';
import Link from 'next/link';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    console.error('Application error:', error);
  }, [error]);

  return (
    <main className="min-h-screen bg-gradient-to-br from-pil-dark to-slate-900 flex items-center justify-center">
      <div className="text-center max-w-lg mx-auto px-6">
        {/* Error Icon */}
        <div className="mb-8">
          <div className="w-24 h-24 rounded-full bg-red-500/20 border-2 border-red-500/50 flex items-center justify-center mx-auto">
            <span className="text-5xl">⚠️</span>
          </div>
        </div>

        <h1 className="text-3xl font-bold text-white mb-4">Something went wrong</h1>
        <p className="text-white/60 mb-6">
          We encountered an unexpected error. This has been logged and we&apos;ll look into it.
        </p>

        {/* Error Details (in development) */}
        {process.env.NODE_ENV === 'development' && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-left">
            <p className="text-red-400 text-sm font-mono break-all">
              {error.message}
            </p>
            {error.digest && (
              <p className="text-white/40 text-xs mt-2">
                Error ID: {error.digest}
              </p>
            )}
          </div>
        )}

        <div className="flex items-center justify-center gap-4">
          <button
            onClick={reset}
            className="px-6 py-3 bg-gradient-pil rounded-xl font-semibold text-white hover:opacity-90 transition"
          >
            Try Again
          </button>
          <Link
            href="/"
            className="px-6 py-3 glass-card rounded-xl font-semibold text-white hover:bg-white/10 transition"
          >
            Go Home
          </Link>
        </div>

        {/* Support Info */}
        <p className="mt-8 text-white/40 text-sm">
          If this problem persists, please{' '}
          <a href="https://github.com" className="text-pil-cyan hover:underline">
            report an issue
          </a>
          .
        </p>
      </div>
    </main>
  );
}
