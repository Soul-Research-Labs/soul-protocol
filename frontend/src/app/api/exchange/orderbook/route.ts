import { NextResponse } from 'next/server';

// Mock order book data
const mockOrderBook = {
  bids: [
    { price: '2050.00', amount: '5.5', total: '11275.00' },
    { price: '2045.00', amount: '3.2', total: '6544.00' },
    { price: '2040.00', amount: '8.1', total: '16524.00' },
    { price: '2035.00', amount: '12.4', total: '25234.00' },
    { price: '2030.00', amount: '6.8', total: '13804.00' },
  ],
  asks: [
    { price: '2055.00', amount: '4.2', total: '8631.00' },
    { price: '2060.00', amount: '7.8', total: '16068.00' },
    { price: '2065.00', amount: '2.5', total: '5162.50' },
    { price: '2070.00', amount: '9.1', total: '18837.00' },
    { price: '2075.00', amount: '5.6', total: '11620.00' },
  ],
  spread: '5.00',
  spreadPercent: '0.24',
  lastPrice: '2052.50',
  lastPriceChange: '+1.25%',
  volume24h: '12450.50',
  high24h: '2085.00',
  low24h: '2015.00',
};

// Mock recent trades
const mockRecentTrades = [
  { id: '1', price: '2052.50', amount: '1.5', side: 'buy', time: Date.now() - 1000 },
  { id: '2', price: '2051.00', amount: '0.8', side: 'sell', time: Date.now() - 5000 },
  { id: '3', price: '2053.00', amount: '2.3', side: 'buy', time: Date.now() - 12000 },
  { id: '4', price: '2050.50', amount: '1.1', side: 'sell', time: Date.now() - 25000 },
  { id: '5', price: '2054.00', amount: '3.5', side: 'buy', time: Date.now() - 45000 },
];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const pair = searchParams.get('pair') || 'WETH/USDC';
  const depth = parseInt(searchParams.get('depth') || '10');
  
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 100));
  
  return NextResponse.json({
    pair,
    timestamp: Date.now(),
    orderBook: mockOrderBook,
    recentTrades: mockRecentTrades,
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { pair, side, price, amount, orderType } = body;
    
    // Validate input
    if (!pair || !side || !amount) {
      return NextResponse.json(
        { error: 'Missing required fields: pair, side, amount' },
        { status: 400 }
      );
    }
    
    // Simulate order placement
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const orderId = `order-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    return NextResponse.json({
      success: true,
      orderId,
      pair,
      side,
      price: price || 'market',
      amount,
      orderType: orderType || 'limit',
      status: 'pending',
      createdAt: Date.now(),
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid request body' },
      { status: 400 }
    );
  }
}
