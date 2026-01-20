'use client';

import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-pil-dark to-slate-900 flex items-center justify-center">
      <div className="text-center">
        {/* 404 Animation */}
        <div className="relative mb-8">
          <span className="text-[150px] font-bold gradient-text opacity-20">404</span>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-24 h-24 rounded-full bg-gradient-pil flex items-center justify-center text-5xl animate-pulse">
              🔍
            </div>
          </div>
        </div>

        <h1 className="text-3xl font-bold text-white mb-4">Page Not Found</h1>
        <p className="text-white/60 mb-8 max-w-md mx-auto">
          The page you&apos;re looking for doesn&apos;t exist or has been moved to a different location.
        </p>

        <div className="flex items-center justify-center gap-4">
          <Link
            href="/"
            className="px-6 py-3 bg-gradient-pil rounded-xl font-semibold text-white hover:opacity-90 transition"
          >
            Go Home
          </Link>
          <Link
            href="/dashboard"
            className="px-6 py-3 glass-card rounded-xl font-semibold text-white hover:bg-white/10 transition"
          >
            Dashboard
          </Link>
        </div>

        {/* Quick Links */}
        <div className="mt-12 text-white/40">
          <p className="text-sm mb-4">Or try one of these:</p>
          <div className="flex items-center justify-center gap-6 text-sm">
            <Link href="/monitoring" className="hover:text-white transition">
              Monitoring
            </Link>
            <span>•</span>
            <Link href="/#bridge" className="hover:text-white transition">
              Bridge
            </Link>
            <span>•</span>
            <Link href="/#containers" className="hover:text-white transition">
              Containers
            </Link>
          </div>
        </div>
      </div>
    </main>
  );
}
