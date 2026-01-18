'use client';

import { ConnectButton } from '@rainbow-me/rainbowkit';
import Link from 'next/link';

export default function Header() {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 glass-card border-t-0 border-x-0 rounded-none">
      <div className="container mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-pil flex items-center justify-center">
            <span className="text-white font-bold text-xl">π</span>
          </div>
          <div>
            <span className="text-xl font-bold gradient-text">PIL v2</span>
            <span className="text-xs text-white/50 block">Privacy Interoperability Layer</span>
          </div>
        </Link>

        {/* Navigation */}
        <nav className="hidden md:flex items-center space-x-8">
          <Link href="#containers" className="text-white/70 hover:text-white transition-colors">
            Containers
          </Link>
          <Link href="#policies" className="text-white/70 hover:text-white transition-colors">
            Policies
          </Link>
          <Link href="#nullifiers" className="text-white/70 hover:text-white transition-colors">
            Nullifiers
          </Link>
          <Link href="#state" className="text-white/70 hover:text-white transition-colors">
            State
          </Link>
        </nav>

        {/* Connect Button */}
        <ConnectButton 
          showBalance={false}
          chainStatus="icon"
          accountStatus="address"
        />
      </div>
    </header>
  );
}
