import { NextResponse } from 'next/server';

// Mock pools data
const mockPools = [
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000001',
    tokenA: { symbol: 'WETH', address: '0x...', decimals: 18 },
    tokenB: { symbol: 'USDC', address: '0x...', decimals: 6 },
    reserveA: '1000000000000000000000', // 1000 WETH
    reserveB: '2000000000000', // 2,000,000 USDC
    totalLPTokens: '44721359549995',
    feeRate: 30,
    tvl: 4000000,
    volume24h: 1250000,
    apr: 12.5,
    active: true,
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000002',
    tokenA: { symbol: 'WETH', address: '0x...', decimals: 18 },
    tokenB: { symbol: 'DAI', address: '0x...', decimals: 18 },
    reserveA: '500000000000000000000', // 500 WETH
    reserveB: '1000000000000000000000000', // 1,000,000 DAI
    totalLPTokens: '22360679774997',
    feeRate: 30,
    tvl: 2000000,
    volume24h: 450000,
    apr: 8.2,
    active: true,
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000003',
    tokenA: { symbol: 'WBTC', address: '0x...', decimals: 8 },
    tokenB: { symbol: 'USDC', address: '0x...', decimals: 6 },
    reserveA: '5000000000', // 50 WBTC
    reserveB: '2175000000000', // 2,175,000 USDC
    totalLPTokens: '32958368660043',
    feeRate: 30,
    tvl: 4350000,
    volume24h: 780000,
    apr: 9.8,
    active: true,
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000004',
    tokenA: { symbol: 'USDC', address: '0x...', decimals: 6 },
    tokenB: { symbol: 'DAI', address: '0x...', decimals: 18 },
    reserveA: '5000000000000', // 5,000,000 USDC
    reserveB: '5000000000000000000000000', // 5,000,000 DAI
    totalLPTokens: '5000000000000000000',
    feeRate: 5, // 0.05% for stableswap
    tvl: 10000000,
    volume24h: 2500000,
    apr: 4.5,
    active: true,
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000005',
    tokenA: { symbol: 'SOUL', address: '0x...', decimals: 18 },
    tokenB: { symbol: 'USDC', address: '0x...', decimals: 6 },
    reserveA: '10000000000000000000000000', // 10,000,000 SOUL
    reserveB: '8500000000000', // 8,500,000 USDC
    totalLPTokens: '92195444572928',
    feeRate: 30,
    tvl: 17000000,
    volume24h: 3200000,
    apr: 15.2,
    active: true,
  },
];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const poolId = searchParams.get('id');
  const sortBy = searchParams.get('sortBy') || 'tvl';
  const order = searchParams.get('order') || 'desc';
  
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 100));
  
  if (poolId) {
    const pool = mockPools.find(p => p.id === poolId);
    if (!pool) {
      return NextResponse.json({ error: 'Pool not found' }, { status: 404 });
    }
    return NextResponse.json(pool);
  }
  
  // Sort pools
  let sortedPools = [...mockPools];
  sortedPools.sort((a, b) => {
    const aVal = a[sortBy as keyof typeof a] as number;
    const bVal = b[sortBy as keyof typeof b] as number;
    return order === 'desc' ? bVal - aVal : aVal - bVal;
  });
  
  // Calculate totals
  const totalTVL = mockPools.reduce((sum, p) => sum + p.tvl, 0);
  const totalVolume24h = mockPools.reduce((sum, p) => sum + p.volume24h, 0);
  
  return NextResponse.json({
    pools: sortedPools,
    stats: {
      totalPools: mockPools.length,
      totalTVL,
      totalVolume24h,
    },
    timestamp: Date.now(),
  });
}

// Calculate swap quote
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { poolId, tokenIn, amountIn } = body;
    
    if (!poolId || !tokenIn || !amountIn) {
      return NextResponse.json(
        { error: 'Missing required fields: poolId, tokenIn, amountIn' },
        { status: 400 }
      );
    }
    
    const pool = mockPools.find(p => p.id === poolId);
    if (!pool) {
      return NextResponse.json({ error: 'Pool not found' }, { status: 404 });
    }
    
    // Determine reserves
    const isTokenA = tokenIn.toLowerCase() === pool.tokenA.symbol.toLowerCase();
    const reserveIn = BigInt(isTokenA ? pool.reserveA : pool.reserveB);
    const reserveOut = BigInt(isTokenA ? pool.reserveB : pool.reserveA);
    const decimalsIn = isTokenA ? pool.tokenA.decimals : pool.tokenB.decimals;
    const decimalsOut = isTokenA ? pool.tokenB.decimals : pool.tokenA.decimals;
    
    // Parse amount
    const amountInWei = BigInt(Math.floor(parseFloat(amountIn) * (10 ** decimalsIn)));
    
    // Calculate output using constant product formula
    const feeMultiplier = BigInt(10000 - pool.feeRate);
    const amountInWithFee = amountInWei * feeMultiplier;
    const numerator = amountInWithFee * reserveOut;
    const denominator = reserveIn * BigInt(10000) + amountInWithFee;
    const amountOutWei = numerator / denominator;
    
    // Calculate price impact
    const idealOutput = (amountInWei * reserveOut) / reserveIn;
    const priceImpact = Number(idealOutput - amountOutWei) / Number(idealOutput) * 100;
    
    // Calculate fee
    const feeWei = (amountInWei * BigInt(pool.feeRate)) / BigInt(10000);
    
    // Format outputs
    const amountOut = Number(amountOutWei) / (10 ** decimalsOut);
    const fee = Number(feeWei) / (10 ** decimalsIn);
    
    return NextResponse.json({
      poolId,
      tokenIn,
      tokenOut: isTokenA ? pool.tokenB.symbol : pool.tokenA.symbol,
      amountIn: parseFloat(amountIn),
      amountOut: amountOut.toFixed(6),
      priceImpact: priceImpact.toFixed(4),
      fee: fee.toFixed(6),
      feeRate: pool.feeRate / 100 + '%',
      route: [tokenIn, isTokenA ? pool.tokenB.symbol : pool.tokenA.symbol],
      timestamp: Date.now(),
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid request body' },
      { status: 400 }
    );
  }
}
