'use client';

import { useAccount } from 'wagmi';
import Header from '@/components/Header';
import Dashboard from '@/components/Dashboard';
import LandingHero from '@/components/LandingHero';

export default function DashboardPage() {
  const { isConnected } = useAccount();

  return (
    <>
      <Header />
      <main className="min-h-screen bg-gradient-to-br from-pil-dark to-slate-900">
        {isConnected ? <Dashboard /> : <LandingHero />}
      </main>
    </>
  );
}
