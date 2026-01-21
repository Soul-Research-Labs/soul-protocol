"use client";

import React, { useState, useEffect, useCallback } from "react";

// Types for the exchange
interface Token {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  logoUrl?: string;
  balance?: string;
}

interface SwapQuote {
  amountOut: string;
  priceImpact: string;
  fee: string;
  route: string[];
  poolId?: string;
}

interface Order {
  id: string;
  maker: string;
  tokenIn: Token;
  tokenOut: Token;
  amountIn: string;
  minAmountOut: string;
  deadline: number;
  status: "Active" | "PartiallyFilled" | "Filled" | "Cancelled" | "Expired";
  filledAmount: string;
  createdAt: number;
  type: "Limit" | "Market";
  side: "Buy" | "Sell";
}

interface Trade {
  id: string;
  maker: string;
  taker: string;
  tokenIn: Token;
  tokenOut: Token;
  amountIn: string;
  amountOut: string;
  makerFee: string;
  takerFee: string;
  executedAt: number;
}

interface Pool {
  id: string;
  tokenA: Token;
  tokenB: Token;
  reserveA: string;
  reserveB: string;
  totalLPTokens: string;
  feeRate: number;
  apr?: string;
}

// Mock tokens for demo
const MOCK_TOKENS: Token[] = [
  { address: "0x0000000000000000000000000000000000000000", symbol: "ETH", name: "Ethereum", decimals: 18 },
  { address: "0x1111111111111111111111111111111111111111", symbol: "WETH", name: "Wrapped Ether", decimals: 18 },
  { address: "0x2222222222222222222222222222222222222222", symbol: "USDC", name: "USD Coin", decimals: 6 },
  { address: "0x3333333333333333333333333333333333333333", symbol: "DAI", name: "Dai Stablecoin", decimals: 18 },
  { address: "0x4444444444444444444444444444444444444444", symbol: "WBTC", name: "Wrapped Bitcoin", decimals: 8 },
  { address: "0x5555555555555555555555555555555555555555", symbol: "SOUL", name: "Soul Network", decimals: 18 },
];

// Privacy settings
interface PrivacySettings {
  useStealthAddress: boolean;
  hideOrderDetails: boolean;
  useZKProofs: boolean;
  encryptMetadata: boolean;
}

export default function ExchangePage() {
  // State
  const [activeTab, setActiveTab] = useState<"swap" | "limit" | "pool" | "orders">("swap");
  const [tokenIn, setTokenIn] = useState<Token>(MOCK_TOKENS[0]);
  const [tokenOut, setTokenOut] = useState<Token>(MOCK_TOKENS[2]);
  const [amountIn, setAmountIn] = useState<string>("");
  const [amountOut, setAmountOut] = useState<string>("");
  const [slippage, setSlippage] = useState<number>(0.5);
  const [quote, setQuote] = useState<SwapQuote | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [orders, setOrders] = useState<Order[]>([]);
  const [trades, setTrades] = useState<Trade[]>([]);
  const [pools, setPools] = useState<Pool[]>([]);
  const [connected, setConnected] = useState(false);
  const [address, setAddress] = useState<string>("");
  const [privacySettings, setPrivacySettings] = useState<PrivacySettings>({
    useStealthAddress: true,
    hideOrderDetails: true,
    useZKProofs: true,
    encryptMetadata: true,
  });
  const [showPrivacyPanel, setShowPrivacyPanel] = useState(false);
  const [txHash, setTxHash] = useState<string>("");
  const [showSuccess, setShowSuccess] = useState(false);

  // Simulated data for demo
  useEffect(() => {
    // Mock pools
    setPools([
      {
        id: "pool-1",
        tokenA: MOCK_TOKENS[1],
        tokenB: MOCK_TOKENS[2],
        reserveA: "1000",
        reserveB: "2000000",
        totalLPTokens: "44721",
        feeRate: 30,
        apr: "12.5",
      },
      {
        id: "pool-2",
        tokenA: MOCK_TOKENS[1],
        tokenB: MOCK_TOKENS[3],
        reserveA: "500",
        reserveB: "1000000",
        totalLPTokens: "22360",
        feeRate: 30,
        apr: "8.2",
      },
    ]);

    // Mock orders
    setOrders([
      {
        id: "order-1",
        maker: "0x1234...5678",
        tokenIn: MOCK_TOKENS[1],
        tokenOut: MOCK_TOKENS[2],
        amountIn: "10",
        minAmountOut: "20000",
        deadline: Date.now() / 1000 + 3600,
        status: "Active",
        filledAmount: "0",
        createdAt: Date.now() / 1000 - 300,
        type: "Limit",
        side: "Sell",
      },
    ]);
  }, []);

  // Calculate quote when input changes
  const calculateQuote = useCallback(async () => {
    if (!amountIn || parseFloat(amountIn) === 0) {
      setQuote(null);
      setAmountOut("");
      return;
    }

    setIsLoading(true);
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 500));

    // Simple constant product calculation for demo
    const inputAmount = parseFloat(amountIn);
    const reserveIn = 1000;
    const reserveOut = 2000000;
    const feeRate = 0.003;

    const amountInWithFee = inputAmount * (1 - feeRate);
    const outputAmount = (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee);
    const priceImpact = (inputAmount / reserveIn) * 100;
    const fee = inputAmount * feeRate;

    setQuote({
      amountOut: outputAmount.toFixed(2),
      priceImpact: priceImpact.toFixed(2),
      fee: fee.toFixed(4),
      route: [tokenIn.symbol, tokenOut.symbol],
      poolId: "pool-1",
    });
    setAmountOut(outputAmount.toFixed(2));
    setIsLoading(false);
  }, [amountIn, tokenIn, tokenOut]);

  useEffect(() => {
    const debounce = setTimeout(calculateQuote, 300);
    return () => clearTimeout(debounce);
  }, [calculateQuote]);

  // Connect wallet
  const connectWallet = async () => {
    setIsLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1000));
    setConnected(true);
    setAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f5DE3E");
    setIsLoading(false);
  };

  // Execute swap
  const executeSwap = async () => {
    if (!connected || !quote) return;
    
    setIsLoading(true);
    
    // Simulate transaction
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const hash = "0x" + Array.from({length: 64}, () => 
      Math.floor(Math.random() * 16).toString(16)
    ).join("");
    
    setTxHash(hash);
    setShowSuccess(true);
    
    // Add to trades
    setTrades(prev => [{
      id: hash,
      maker: address,
      taker: address,
      tokenIn,
      tokenOut,
      amountIn,
      amountOut: quote.amountOut,
      makerFee: "0",
      takerFee: quote.fee,
      executedAt: Date.now() / 1000,
    }, ...prev]);
    
    setAmountIn("");
    setAmountOut("");
    setQuote(null);
    setIsLoading(false);
    
    setTimeout(() => setShowSuccess(false), 5000);
  };

  // Create limit order
  const createLimitOrder = async () => {
    if (!connected || !amountIn) return;
    
    setIsLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    const orderId = "order-" + Math.random().toString(36).substr(2, 9);
    
    setOrders(prev => [{
      id: orderId,
      maker: address,
      tokenIn,
      tokenOut,
      amountIn,
      minAmountOut: amountOut,
      deadline: Date.now() / 1000 + 3600,
      status: "Active",
      filledAmount: "0",
      createdAt: Date.now() / 1000,
      type: "Limit",
      side: "Sell",
    }, ...prev]);
    
    setAmountIn("");
    setAmountOut("");
    setIsLoading(false);
    setShowSuccess(true);
    setTimeout(() => setShowSuccess(false), 3000);
  };

  // Swap tokens position
  const swapTokens = () => {
    const temp = tokenIn;
    setTokenIn(tokenOut);
    setTokenOut(temp);
    setAmountIn("");
    setAmountOut("");
    setQuote(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      {/* Header */}
      <header className="border-b border-purple-800/30 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-10 h-10 rounded-full bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center">
              <span className="text-white font-bold">PIL</span>
            </div>
            <span className="text-xl font-bold text-white">Private Exchange</span>
          </div>
          
          <nav className="flex items-center space-x-6">
            <button
              onClick={() => setShowPrivacyPanel(!showPrivacyPanel)}
              className="flex items-center space-x-2 text-purple-300 hover:text-white transition"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span>Privacy</span>
            </button>
            
            {connected ? (
              <div className="flex items-center space-x-2 bg-purple-800/50 px-4 py-2 rounded-lg">
                <div className="w-2 h-2 rounded-full bg-green-400"></div>
                <span className="text-white text-sm font-mono">
                  {address.slice(0, 6)}...{address.slice(-4)}
                </span>
              </div>
            ) : (
              <button
                onClick={connectWallet}
                disabled={isLoading}
                className="bg-gradient-to-r from-purple-500 to-pink-500 text-white px-6 py-2 rounded-lg 
                  font-medium hover:from-purple-600 hover:to-pink-600 transition disabled:opacity-50"
              >
                {isLoading ? "Connecting..." : "Connect Wallet"}
              </button>
            )}
          </nav>
        </div>
      </header>

      {/* Privacy Settings Panel */}
      {showPrivacyPanel && (
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="bg-purple-900/50 border border-purple-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              PIL Privacy Settings
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { key: "useStealthAddress", label: "Stealth Addresses", desc: "Hide recipient identity" },
                { key: "hideOrderDetails", label: "Private Orders", desc: "Encrypt order details" },
                { key: "useZKProofs", label: "ZK Proofs", desc: "Verify without revealing" },
                { key: "encryptMetadata", label: "Encrypt Metadata", desc: "Hide transaction data" },
              ].map(({ key, label, desc }) => (
                <div key={key} className="bg-purple-800/30 p-4 rounded-lg">
                  <label className="flex items-center justify-between cursor-pointer">
                    <div>
                      <div className="text-white font-medium">{label}</div>
                      <div className="text-purple-300 text-xs">{desc}</div>
                    </div>
                    <input
                      type="checkbox"
                      checked={privacySettings[key as keyof PrivacySettings]}
                      onChange={(e) => setPrivacySettings({
                        ...privacySettings,
                        [key]: e.target.checked
                      })}
                      className="w-5 h-5 rounded bg-purple-700 border-purple-600 text-purple-500 
                        focus:ring-purple-500 focus:ring-offset-0"
                    />
                  </label>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* Success Toast */}
        {showSuccess && (
          <div className="fixed top-20 right-4 bg-green-600 text-white px-6 py-4 rounded-lg shadow-xl 
            flex items-center space-x-3 animate-slide-in z-50">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            <div>
              <div className="font-medium">Transaction Successful!</div>
              {txHash && (
                <div className="text-sm text-green-200 font-mono">
                  {txHash.slice(0, 10)}...{txHash.slice(-8)}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex justify-center mb-8">
          <div className="bg-gray-800/50 p-1 rounded-xl inline-flex">
            {(["swap", "limit", "pool", "orders"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-6 py-2 rounded-lg font-medium transition ${
                  activeTab === tab
                    ? "bg-purple-600 text-white"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Swap / Order Panel */}
          <div className="lg:col-span-2">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-800/30 rounded-2xl p-6">
              {(activeTab === "swap" || activeTab === "limit") && (
                <>
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-semibold text-white">
                      {activeTab === "swap" ? "Private Swap" : "Private Limit Order"}
                    </h2>
                    <button
                      onClick={() => {/* Settings modal */}}
                      className="text-purple-400 hover:text-white p-2 rounded-lg hover:bg-purple-800/30"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                          d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                    </button>
                  </div>

                  {/* From Token */}
                  <div className="bg-gray-900/50 rounded-xl p-4 mb-2">
                    <div className="flex justify-between text-sm text-gray-400 mb-2">
                      <span>You Pay</span>
                      <span>Balance: 100.00 {tokenIn.symbol}</span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <input
                        type="number"
                        value={amountIn}
                        onChange={(e) => setAmountIn(e.target.value)}
                        placeholder="0.0"
                        className="flex-1 bg-transparent text-3xl text-white outline-none"
                      />
                      <button className="flex items-center space-x-2 bg-purple-700/50 px-4 py-2 rounded-xl 
                        hover:bg-purple-600/50 transition">
                        <span className="w-6 h-6 rounded-full bg-purple-500 flex items-center justify-center text-xs">
                          {tokenIn.symbol.charAt(0)}
                        </span>
                        <span className="text-white font-medium">{tokenIn.symbol}</span>
                        <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  {/* Swap Button */}
                  <div className="flex justify-center -my-3 relative z-10">
                    <button
                      onClick={swapTokens}
                      className="w-10 h-10 rounded-full bg-gray-700 border-4 border-gray-800 
                        flex items-center justify-center hover:bg-purple-600 transition"
                    >
                      <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                          d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                      </svg>
                    </button>
                  </div>

                  {/* To Token */}
                  <div className="bg-gray-900/50 rounded-xl p-4 mb-4">
                    <div className="flex justify-between text-sm text-gray-400 mb-2">
                      <span>You Receive</span>
                      <span>Balance: 50,000.00 {tokenOut.symbol}</span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <input
                        type="number"
                        value={amountOut}
                        onChange={(e) => setAmountOut(e.target.value)}
                        placeholder="0.0"
                        readOnly={activeTab === "swap"}
                        className="flex-1 bg-transparent text-3xl text-white outline-none"
                      />
                      <button className="flex items-center space-x-2 bg-purple-700/50 px-4 py-2 rounded-xl 
                        hover:bg-purple-600/50 transition">
                        <span className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center text-xs">
                          {tokenOut.symbol.charAt(0)}
                        </span>
                        <span className="text-white font-medium">{tokenOut.symbol}</span>
                        <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  {/* Quote Details */}
                  {quote && (
                    <div className="bg-purple-900/30 rounded-xl p-4 mb-4 space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Price</span>
                        <span className="text-white">
                          1 {tokenIn.symbol} = {(parseFloat(quote.amountOut) / parseFloat(amountIn)).toFixed(2)} {tokenOut.symbol}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Price Impact</span>
                        <span className={`${parseFloat(quote.priceImpact) > 5 ? "text-red-400" : "text-green-400"}`}>
                          {quote.priceImpact}%
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Fee (0.3%)</span>
                        <span className="text-white">{quote.fee} {tokenIn.symbol}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Route</span>
                        <span className="text-white">{quote.route.join(" → ")}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Slippage Tolerance</span>
                        <span className="text-white">{slippage}%</span>
                      </div>
                      {privacySettings.useZKProofs && (
                        <div className="flex justify-between text-sm">
                          <span className="text-purple-400 flex items-center">
                            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            Privacy Protected
                          </span>
                          <span className="text-purple-300">ZK Proof Required</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Slippage Settings */}
                  <div className="flex items-center justify-between mb-4 bg-gray-900/30 rounded-lg p-3">
                    <span className="text-gray-400 text-sm">Slippage Tolerance</span>
                    <div className="flex items-center space-x-2">
                      {[0.1, 0.5, 1.0].map((val) => (
                        <button
                          key={val}
                          onClick={() => setSlippage(val)}
                          className={`px-3 py-1 rounded text-sm transition ${
                            slippage === val 
                              ? "bg-purple-600 text-white" 
                              : "bg-gray-700 text-gray-400 hover:text-white"
                          }`}
                        >
                          {val}%
                        </button>
                      ))}
                      <input
                        type="number"
                        value={slippage}
                        onChange={(e) => setSlippage(parseFloat(e.target.value) || 0.5)}
                        className="w-16 bg-gray-700 text-white text-center rounded py-1 text-sm"
                      />
                    </div>
                  </div>

                  {/* Action Button */}
                  <button
                    onClick={activeTab === "swap" ? executeSwap : createLimitOrder}
                    disabled={!connected || !amountIn || isLoading}
                    className="w-full py-4 rounded-xl font-semibold text-lg transition
                      bg-gradient-to-r from-purple-600 to-pink-600 text-white
                      hover:from-purple-700 hover:to-pink-700
                      disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? (
                      <span className="flex items-center justify-center">
                        <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Processing...
                      </span>
                    ) : !connected ? (
                      "Connect Wallet"
                    ) : !amountIn ? (
                      "Enter Amount"
                    ) : activeTab === "swap" ? (
                      "Private Swap"
                    ) : (
                      "Create Private Order"
                    )}
                  </button>
                </>
              )}

              {activeTab === "pool" && (
                <div>
                  <h2 className="text-xl font-semibold text-white mb-6">Liquidity Pools</h2>
                  <div className="space-y-4">
                    {pools.map((pool) => (
                      <div key={pool.id} className="bg-gray-900/50 rounded-xl p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center space-x-2">
                            <div className="flex -space-x-2">
                              <div className="w-8 h-8 rounded-full bg-purple-500 flex items-center justify-center text-xs font-bold border-2 border-gray-900">
                                {pool.tokenA.symbol.charAt(0)}
                              </div>
                              <div className="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-xs font-bold border-2 border-gray-900">
                                {pool.tokenB.symbol.charAt(0)}
                              </div>
                            </div>
                            <span className="text-white font-medium">
                              {pool.tokenA.symbol}/{pool.tokenB.symbol}
                            </span>
                          </div>
                          <span className="text-green-400 text-sm">{pool.apr}% APR</span>
                        </div>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-gray-400">Liquidity</span>
                            <div className="text-white">
                              {pool.reserveA} {pool.tokenA.symbol} / {pool.reserveB} {pool.tokenB.symbol}
                            </div>
                          </div>
                          <div>
                            <span className="text-gray-400">Fee</span>
                            <div className="text-white">{pool.feeRate / 100}%</div>
                          </div>
                        </div>
                        <div className="mt-4 flex space-x-2">
                          <button className="flex-1 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition">
                            Add Liquidity
                          </button>
                          <button className="flex-1 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition">
                            Remove
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === "orders" && (
                <div>
                  <h2 className="text-xl font-semibold text-white mb-6">My Private Orders</h2>
                  <div className="space-y-4">
                    {orders.length === 0 ? (
                      <div className="text-center py-12 text-gray-400">
                        <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                            d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                        </svg>
                        <p>No orders yet</p>
                      </div>
                    ) : (
                      orders.map((order) => (
                        <div key={order.id} className="bg-gray-900/50 rounded-xl p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center space-x-2">
                              <span className={`px-2 py-1 rounded text-xs font-medium ${
                                order.side === "Buy" ? "bg-green-600/20 text-green-400" : "bg-red-600/20 text-red-400"
                              }`}>
                                {order.side}
                              </span>
                              <span className="text-white">
                                {order.amountIn} {order.tokenIn.symbol} → {order.minAmountOut} {order.tokenOut.symbol}
                              </span>
                            </div>
                            <span className={`text-sm ${
                              order.status === "Active" ? "text-green-400" :
                              order.status === "Filled" ? "text-blue-400" :
                              "text-gray-400"
                            }`}>
                              {order.status}
                            </span>
                          </div>
                          <div className="flex items-center justify-between text-sm text-gray-400">
                            <span>Created {new Date(order.createdAt * 1000).toLocaleString()}</span>
                            <span>Expires in {Math.floor((order.deadline - Date.now() / 1000) / 60)} min</span>
                          </div>
                          {order.status === "Active" && (
                            <button className="mt-3 w-full py-2 bg-red-600/20 text-red-400 rounded-lg 
                              hover:bg-red-600/30 transition">
                              Cancel Order
                            </button>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Privacy Status */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-800/30 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                <svg className="w-5 h-5 mr-2 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                PIL Privacy Status
              </h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Stealth Address</span>
                  <span className={privacySettings.useStealthAddress ? "text-green-400" : "text-gray-500"}>
                    {privacySettings.useStealthAddress ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Order Encryption</span>
                  <span className={privacySettings.hideOrderDetails ? "text-green-400" : "text-gray-500"}>
                    {privacySettings.hideOrderDetails ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">ZK Proofs</span>
                  <span className={privacySettings.useZKProofs ? "text-green-400" : "text-gray-500"}>
                    {privacySettings.useZKProofs ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Nullifier</span>
                  <span className="text-green-400">Protected</span>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-gray-700">
                <div className="flex items-center text-sm">
                  <div className="w-3 h-3 rounded-full bg-green-500 mr-2 animate-pulse"></div>
                  <span className="text-gray-300">Privacy Level: <span className="text-green-400 font-medium">Maximum</span></span>
                </div>
              </div>
            </div>

            {/* Recent Trades */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-800/30 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Recent Trades</h3>
              {trades.length === 0 ? (
                <p className="text-gray-400 text-sm text-center py-4">No trades yet</p>
              ) : (
                <div className="space-y-3">
                  {trades.slice(0, 5).map((trade) => (
                    <div key={trade.id} className="bg-gray-900/50 rounded-lg p-3">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-white">
                          {trade.amountIn} {trade.tokenIn.symbol} → {trade.amountOut} {trade.tokenOut.symbol}
                        </span>
                        <span className="text-gray-400 text-xs">
                          {new Date(trade.executedAt * 1000).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 font-mono mt-1">
                        {trade.id.slice(0, 10)}...
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Network Stats */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-purple-800/30 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Network Stats</h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-gray-400">Total Volume (24h)</span>
                  <span className="text-white">$12.4M</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Private Trades</span>
                  <span className="text-white">1,247</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Active Pools</span>
                  <span className="text-white">{pools.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Cross-Chain Swaps</span>
                  <span className="text-white">89</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-purple-800/30 mt-16 py-8">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-between text-gray-400 text-sm">
          <div>© 2025 Soul Network - Privacy Interoperability Layer</div>
          <div className="flex items-center space-x-4">
            <a href="#" className="hover:text-white">Docs</a>
            <a href="#" className="hover:text-white">GitHub</a>
            <a href="#" className="hover:text-white">Discord</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
