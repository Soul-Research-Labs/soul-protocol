'use client';

import { ConnectButton } from '@rainbow-me/rainbowkit';

export default function LandingHero() {
  return (
    <div className="pt-24 pb-16">
      <div className="container mx-auto px-6">
        {/* Hero Section */}
        <div className="text-center max-w-4xl mx-auto py-20">
          <h1 className="text-5xl md:text-7xl font-bold mb-6">
            <span className="gradient-text">Privacy</span>{' '}
            <span className="text-white">Interoperability</span>
            <br />
            <span className="text-white/80">Layer</span>
          </h1>
          <p className="text-xl text-white/60 mb-8 max-w-2xl mx-auto">
            Self-authenticating confidential containers with embedded ZK proofs 
            for seamless cross-chain privacy-preserving operations.
          </p>
          <div className="flex items-center justify-center gap-4">
            <ConnectButton label="Connect to Get Started" />
          </div>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mt-12">
          <FeatureCard
            icon="📦"
            title="PC³"
            subtitle="Proof Carrying Containers"
            description="Self-authenticating confidential containers that carry their own correctness and policy proofs"
          />
          <FeatureCard
            icon="📋"
            title="PBP"
            subtitle="Policy Bound Proofs"
            description="Dynamic policy expressions with jurisdiction-aware compliance proofs"
          />
          <FeatureCard
            icon="🔄"
            title="EASC"
            subtitle="Execution Agnostic State"
            description="State commitments that work across any execution environment"
          />
          <FeatureCard
            icon="🌐"
            title="CDNA"
            subtitle="Cross-Domain Nullifiers"
            description="Unified nullifier system preventing double-spending across chains"
          />
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-16">
          <StatCard value="4" label="Core Primitives" />
          <StatCard value="200+" label="Test Cases" />
          <StatCard value="48hr" label="Timelock Delay" />
          <StatCard value="∞" label="Chain Support" />
        </div>
      </div>
    </div>
  );
}

function FeatureCard({ 
  icon, 
  title, 
  subtitle, 
  description 
}: { 
  icon: string; 
  title: string; 
  subtitle: string; 
  description: string;
}) {
  return (
    <div className="glass-card p-6 hover:bg-white/10 transition-all duration-300 cursor-pointer group">
      <div className="text-4xl mb-4">{icon}</div>
      <h3 className="text-xl font-bold text-white group-hover:text-pil-cyan transition-colors">
        {title}
      </h3>
      <p className="text-sm text-pil-purple mb-2">{subtitle}</p>
      <p className="text-white/60 text-sm">{description}</p>
    </div>
  );
}

function StatCard({ value, label }: { value: string; label: string }) {
  return (
    <div className="glass-card p-6 text-center">
      <div className="text-3xl font-bold gradient-text">{value}</div>
      <div className="text-white/50 text-sm mt-1">{label}</div>
    </div>
  );
}
