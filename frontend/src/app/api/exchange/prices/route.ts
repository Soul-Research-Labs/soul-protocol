import { NextResponse } from 'next/server';

// Mock price feeds with some variance
function generatePrice(basePrice: number, variance: number = 0.01): string {
  const change = basePrice * variance * (Math.random() * 2 - 1);
  return (basePrice + change).toFixed(2);
}

// Token price data
const basePrices: Record<string, number> = {
  'ETH': 2050,
  'WETH': 2050,
  'BTC': 43500,
  'WBTC': 43500,
  'USDC': 1.0,
  'USDT': 1.0,
  'DAI': 1.0,
  'SOUL': 0.85,
};

// 24h price history (simulated)
function generate24hHistory(basePrice: number): Array<{ time: number; price: number }> {
  const history = [];
  const now = Date.now();
  const interval = 3600000; // 1 hour
  
  for (let i = 24; i >= 0; i--) {
    const variance = 0.02;
    const price = basePrice * (1 + variance * (Math.random() * 2 - 1));
    history.push({
      time: now - (i * interval),
      price: parseFloat(price.toFixed(2)),
    });
  }
  
  return history;
}

// Candlestick data
function generateCandlesticks(basePrice: number, count: number = 24): Array<{
  time: number;
  open: number;
  high: number;
  low: number;
  close: number;
  volume: number;
}> {
  const candles = [];
  const now = Date.now();
  const interval = 3600000; // 1 hour
  let currentPrice = basePrice * 0.98;
  
  for (let i = count; i >= 0; i--) {
    const open = currentPrice;
    const change = open * 0.02 * (Math.random() * 2 - 1);
    const close = open + change;
    const high = Math.max(open, close) * (1 + Math.random() * 0.01);
    const low = Math.min(open, close) * (1 - Math.random() * 0.01);
    const volume = Math.random() * 1000 + 100;
    
    candles.push({
      time: now - (i * interval),
      open: parseFloat(open.toFixed(2)),
      high: parseFloat(high.toFixed(2)),
      low: parseFloat(low.toFixed(2)),
      close: parseFloat(close.toFixed(2)),
      volume: parseFloat(volume.toFixed(2)),
    });
    
    currentPrice = close;
  }
  
  return candles;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const token = searchParams.get('token')?.toUpperCase() || 'ETH';
  const includeHistory = searchParams.get('history') === 'true';
  const includeCandles = searchParams.get('candles') === 'true';
  
  const basePrice = basePrices[token] || 1.0;
  const currentPrice = parseFloat(generatePrice(basePrice));
  const previousPrice = basePrice;
  const priceChange = currentPrice - previousPrice;
  const priceChangePercent = (priceChange / previousPrice) * 100;
  
  const response: Record<string, any> = {
    token,
    price: currentPrice.toFixed(2),
    priceUSD: currentPrice.toFixed(2),
    change24h: priceChange.toFixed(2),
    changePercent24h: priceChangePercent.toFixed(2),
    high24h: (currentPrice * 1.02).toFixed(2),
    low24h: (currentPrice * 0.98).toFixed(2),
    volume24h: (Math.random() * 10000000 + 1000000).toFixed(2),
    marketCap: (currentPrice * 120000000).toFixed(0),
    timestamp: Date.now(),
  };
  
  if (includeHistory) {
    response.history = generate24hHistory(basePrice);
  }
  
  if (includeCandles) {
    response.candles = generateCandlesticks(basePrice);
  }
  
  return NextResponse.json(response);
}

// Get prices for multiple tokens
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const tokens: string[] = body.tokens || ['ETH', 'USDC', 'DAI'];
    
    const prices: Record<string, any> = {};
    
    for (const token of tokens) {
      const upperToken = token.toUpperCase();
      const basePrice = basePrices[upperToken] || 1.0;
      const currentPrice = parseFloat(generatePrice(basePrice));
      const priceChange = (Math.random() * 4 - 2);
      
      prices[upperToken] = {
        price: currentPrice.toFixed(2),
        change24h: priceChange.toFixed(2),
      };
    }
    
    return NextResponse.json({
      prices,
      timestamp: Date.now(),
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid request body' },
      { status: 400 }
    );
  }
}
