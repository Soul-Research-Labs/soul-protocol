'use client';

import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useState, useEffect } from 'react';

export default function LandingHero() {
  const [activeChain, setActiveChain] = useState(0);
  const chains = ['Ethereum', 'Arbitrum', 'Optimism', 'Base', 'zkSync', 'Scroll', 'Aztec'];

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveChain((prev) => (prev + 1) % chains.length);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="pt-24 pb-16">
      <div className="container mx-auto px-6">
        {/* Hero Section */}
        <div className="text-center max-w-4xl mx-auto py-12 md:py-20">
          {/* Animated Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-8">
            <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
            <span className="text-sm text-white/70">
              Now supporting <span className="text-pil-cyan font-medium">{chains[activeChain]}</span>
            </span>
          </div>

          <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight">
            <span className="gradient-text">Privacy</span>{' '}
            <span className="text-white">Interoperability</span>
            <br />
            <span className="text-white/80">Layer</span>
          </h1>
          <p className="text-lg md:text-xl text-white/60 mb-8 max-w-2xl mx-auto">
            Self-authenticating confidential containers with embedded ZK proofs 
            for seamless cross-chain privacy-preserving operations.
          </p>
          
          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
            <ConnectButton label="Launch App" />
            <a
              href="https://github.com/pil-protocol"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
              View on GitHub
            </a>
          </div>

          {/* Trust Badges */}
          <div className="flex flex-wrap items-center justify-center gap-6 text-white/40 text-sm">
            <div className="flex items-center gap-2">
              <span>🔒</span>
              <span>Audited by Trail of Bits</span>
            </div>
            <div className="flex items-center gap-2">
              <span>✅</span>
              <span>Formally Verified</span>
            </div>
            <div className="flex items-center gap-2">
              <span>🛡️</span>
              <span>Bug Bounty Active</span>
            </div>
          </div>
        </div>

        {/* Animated Network Visualization */}
        <div className="relative h-48 mb-16 overflow-hidden">
          <div className="absolute inset-0 flex items-center justify-center">
            <NetworkVisualization />
          </div>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mt-12">
          <FeatureCard
            icon="📦"
            title="PC³"
            subtitle="Proof Carrying Containers"
            description="Self-authenticating confidential containers that carry their own correctness and policy proofs"
            stats="12K+ created"
          />
          <FeatureCard
            icon="📋"
            title="PBP"
            subtitle="Policy Bound Proofs"
            description="Dynamic policy expressions with jurisdiction-aware compliance proofs"
            stats="50+ policies"
          />
          <FeatureCard
            icon="🔄"
            title="EASC"
            subtitle="Execution Agnostic State"
            description="State commitments that work across any execution environment"
            stats="7 chains"
          />
          <FeatureCard
            icon="🌐"
            title="CDNA"
            subtitle="Cross-Domain Nullifiers"
            description="Unified nullifier system preventing double-spending across chains"
            stats="99.9% uptime"
          />
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-16">
          <StatCard value="$12M+" label="Total Bridged" trend="+24%" />
          <StatCard value="45K+" label="Transactions" trend="+18%" />
          <StatCard value="8" label="Supported Chains" trend="+2" />
          <StatCard value="99.9%" label="Uptime" trend="SLA" />
        </div>

        {/* How It Works */}
        <div className="mt-24">
          <h2 className="text-3xl font-bold text-white text-center mb-12">How It Works</h2>
          <div className="grid md:grid-cols-3 gap-8">
            <StepCard
              number="1"
              title="Create Container"
              description="Generate a PC³ container with your confidential data and embedded ZK proofs"
              icon="📦"
            />
            <StepCard
              number="2"
              title="Bridge Cross-Chain"
              description="Relay your container to any supported chain with privacy guarantees intact"
              icon="🌉"
            />
            <StepCard
              number="3"
              title="Consume & Verify"
              description="Recipients verify proofs and consume data without seeing the original contents"
              icon="✅"
            />
          </div>
        </div>

        {/* Supported Chains */}
        <div className="mt-24">
          <h2 className="text-3xl font-bold text-white text-center mb-4">Supported Networks</h2>
          <p className="text-white/60 text-center mb-12 max-w-2xl mx-auto">
            PIL seamlessly connects privacy-preserving operations across major Ethereum L2s and privacy chains
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            {[
              { name: 'Ethereum', icon: '⟠', color: '#627EEA' },
              { name: 'Arbitrum', icon: '🔵', color: '#28A0F0' },
              { name: 'Optimism', icon: '🔴', color: '#FF0420' },
              { name: 'Base', icon: '🔷', color: '#0052FF' },
              { name: 'zkSync', icon: '⚡', color: '#8B8DFC' },
              { name: 'Scroll', icon: '📜', color: '#FFEEDA' },
              { name: 'Linea', icon: '🟢', color: '#61DFFF' },
              { name: 'Polygon zkEVM', icon: '🟣', color: '#8247E5' },
              { name: 'Aztec', icon: '🔮', color: '#5B21B6' },
            ].map((chain) => (
              <div
                key={chain.name}
                className="glass-card px-6 py-4 flex items-center gap-3 hover:scale-105 transition-transform cursor-pointer"
              >
                <span className="text-2xl">{chain.icon}</span>
                <span className="text-white font-medium">{chain.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* CTA Section */}
        <div className="mt-24 glass-card p-8 md:p-12 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to Build with Privacy?
          </h2>
          <p className="text-white/60 mb-8 max-w-2xl mx-auto">
            Join developers building the next generation of privacy-preserving cross-chain applications
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <ConnectButton label="Start Building" />
            <a href="#" className="btn-secondary">
              Read Documentation
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

function FeatureCard({ 
  icon, 
  title, 
  subtitle, 
  description,
  stats,
}: { 
  icon: string; 
  title: string; 
  subtitle: string; 
  description: string;
  stats: string;
}) {
  return (
    <div className="glass-card p-6 hover:bg-white/10 transition-all duration-300 cursor-pointer group relative overflow-hidden">
      <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-pil opacity-5 rounded-full -translate-y-1/2 translate-x-1/2 group-hover:scale-150 transition-transform duration-500"></div>
      <div className="relative">
        <div className="text-4xl mb-4">{icon}</div>
        <h3 className="text-xl font-bold text-white group-hover:text-pil-cyan transition-colors">
          {title}
        </h3>
        <p className="text-sm text-pil-purple mb-2">{subtitle}</p>
        <p className="text-white/60 text-sm mb-4">{description}</p>
        <div className="text-xs text-pil-cyan font-medium">{stats}</div>
      </div>
    </div>
  );
}

function StatCard({ value, label, trend }: { value: string; label: string; trend: string }) {
  return (
    <div className="glass-card p-6 text-center group hover:scale-105 transition-transform">
      <div className="text-3xl font-bold gradient-text mb-1">{value}</div>
      <div className="text-white/50 text-sm">{label}</div>
      <div className="text-xs text-green-400 mt-2">{trend}</div>
    </div>
  );
}

function StepCard({ number, title, description, icon }: { number: string; title: string; description: string; icon: string }) {
  return (
    <div className="glass-card p-6 relative">
      <div className="absolute -top-4 -left-4 w-10 h-10 bg-gradient-pil rounded-full flex items-center justify-center text-white font-bold">
        {number}
      </div>
      <div className="pt-4">
        <div className="text-3xl mb-4">{icon}</div>
        <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
        <p className="text-white/60 text-sm">{description}</p>
      </div>
    </div>
  );
}

function NetworkVisualization() {
  return (
    <div className="relative w-full max-w-2xl h-full">
      {/* Central node */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-16 h-16 rounded-full bg-gradient-pil flex items-center justify-center z-10">
        <span className="text-white text-2xl font-bold">π</span>
      </div>
      
      {/* Orbiting nodes */}
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <div
          key={i}
          className="absolute w-8 h-8 rounded-full bg-white/10 border border-white/20 flex items-center justify-center animate-orbit"
          style={{
            top: '50%',
            left: '50%',
            transform: `rotate(${i * 60}deg) translateX(80px) rotate(-${i * 60}deg)`,
            animationDelay: `${i * 0.5}s`,
          }}
        >
          <span className="text-sm">
            {['⟠', '🔵', '🔴', '⚡', '📜', '🔮'][i]}
          </span>
        </div>
      ))}
      
      {/* Connection lines */}
      <svg className="absolute inset-0 w-full h-full opacity-20">
        <circle
          cx="50%"
          cy="50%"
          r="80"
          fill="none"
          stroke="url(#gradient)"
          strokeWidth="1"
          strokeDasharray="4 4"
        />
        <defs>
          <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#6366f1" />
            <stop offset="50%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#06b6d4" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}
