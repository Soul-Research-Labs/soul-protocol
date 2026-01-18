'use client';

import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount } from 'wagmi';
import Header from '@/components/Header';
import Dashboard from '@/components/Dashboard';
import LandingHero from '@/components/LandingHero';

export default function Home() {
  const { isConnected } = useAccount();

  return (
    <main className="min-h-screen">
      <Header />
      {isConnected ? <Dashboard /> : <LandingHero />}
    </main>
  );
}
