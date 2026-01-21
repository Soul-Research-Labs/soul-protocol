/**
 * PIL Exchange WebSocket Support
 * 
 * Real-time updates for:
 * - Order book changes
 * - Trade executions
 * - Pool state updates
 * - Stealth address announcements
 */

import { ethers } from "ethers";

// ============================================================================
// Types
// ============================================================================

export interface WebSocketConfig {
  url: string;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  heartbeatInterval?: number;
}

export interface Subscription {
  channel: SubscriptionChannel;
  params?: Record<string, unknown>;
}

export type SubscriptionChannel = 
  | "trades"
  | "orders"
  | "pools"
  | "stealth"
  | "user";

export interface TradeUpdate {
  poolId: string;
  tokenIn: string;
  tokenOut: string;
  amountIn: string;
  amountOut: string;
  trader: string;
  timestamp: number;
  txHash: string;
}

export interface OrderUpdate {
  type: "new" | "cancel" | "fill" | "partial";
  orderId: string;
  pair: string;
  side: "buy" | "sell";
  price: string;
  amount: string;
  filled?: string;
  timestamp: number;
}

export interface PoolUpdate {
  poolId: string;
  tokenA: string;
  tokenB: string;
  reserveA: string;
  reserveB: string;
  liquidity: string;
  timestamp: number;
}

export interface StealthAnnouncement {
  stealthAddress: string;
  token: string;
  amount: string;
  ephemeralPubKeyX: string;
  ephemeralPubKeyY: string;
  viewTag: number;
  blockNumber: number;
  txHash: string;
}

export type MessageHandler<T> = (data: T) => void;

// ============================================================================
// WebSocket Client
// ============================================================================

export class PILExchangeWebSocket {
  private ws: WebSocket | null = null;
  private config: Required<WebSocketConfig>;
  private reconnectAttempts = 0;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private subscriptions: Map<string, Subscription> = new Map();
  private handlers: Map<SubscriptionChannel, Set<MessageHandler<any>>> = new Map();
  private isConnecting = false;
  private shouldReconnect = true;

  constructor(config: WebSocketConfig) {
    this.config = {
      url: config.url,
      reconnectInterval: config.reconnectInterval ?? 3000,
      maxReconnectAttempts: config.maxReconnectAttempts ?? 10,
      heartbeatInterval: config.heartbeatInterval ?? 30000,
    };
  }

  /**
   * Connect to WebSocket server
   */
  async connect(): Promise<void> {
    if (this.isConnecting || (this.ws?.readyState === WebSocket.OPEN)) {
      return;
    }

    this.isConnecting = true;
    this.shouldReconnect = true;

    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.config.url);

        this.ws.onopen = () => {
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          console.log("[PIL-WS] Connected");
          this.startHeartbeat();
          this.resubscribeAll();
          resolve();
        };

        this.ws.onmessage = (event) => {
          this.handleMessage(event.data);
        };

        this.ws.onerror = (error) => {
          console.error("[PIL-WS] Error:", error);
          if (this.isConnecting) {
            reject(error);
          }
        };

        this.ws.onclose = (event) => {
          this.isConnecting = false;
          this.stopHeartbeat();
          console.log("[PIL-WS] Disconnected:", event.code, event.reason);
          
          if (this.shouldReconnect) {
            this.scheduleReconnect();
          }
        };
      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    this.shouldReconnect = false;
    this.stopHeartbeat();
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close(1000, "Client disconnect");
      this.ws = null;
    }
  }

  /**
   * Subscribe to a channel
   */
  subscribe(channel: SubscriptionChannel, params?: Record<string, unknown>): string {
    const subscriptionId = `${channel}_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    
    this.subscriptions.set(subscriptionId, { channel, params });
    
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.sendSubscription(channel, params);
    }

    return subscriptionId;
  }

  /**
   * Unsubscribe from a channel
   */
  unsubscribe(subscriptionId: string): void {
    const subscription = this.subscriptions.get(subscriptionId);
    if (!subscription) return;

    this.subscriptions.delete(subscriptionId);

    // Check if any other subscriptions exist for this channel
    const hasOtherSubs = Array.from(this.subscriptions.values())
      .some(sub => sub.channel === subscription.channel);

    if (!hasOtherSubs && this.ws?.readyState === WebSocket.OPEN) {
      this.send({
        type: "unsubscribe",
        channel: subscription.channel,
      });
    }
  }

  /**
   * Add message handler for a channel
   */
  on<T>(channel: "trades", handler: MessageHandler<TradeUpdate>): void;
  on<T>(channel: "orders", handler: MessageHandler<OrderUpdate>): void;
  on<T>(channel: "pools", handler: MessageHandler<PoolUpdate>): void;
  on<T>(channel: "stealth", handler: MessageHandler<StealthAnnouncement>): void;
  on(channel: SubscriptionChannel, handler: MessageHandler<any>): void {
    if (!this.handlers.has(channel)) {
      this.handlers.set(channel, new Set());
    }
    this.handlers.get(channel)!.add(handler);
  }

  /**
   * Remove message handler
   */
  off(channel: SubscriptionChannel, handler: MessageHandler<any>): void {
    this.handlers.get(channel)?.delete(handler);
  }

  /**
   * Check if connected
   */
  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  private send(data: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  private sendSubscription(channel: SubscriptionChannel, params?: Record<string, unknown>): void {
    this.send({
      type: "subscribe",
      channel,
      params,
    });
  }

  private handleMessage(rawData: string): void {
    try {
      const message = JSON.parse(rawData);

      // Handle different message types
      if (message.type === "pong") {
        // Heartbeat response
        return;
      }

      if (message.type === "subscribed") {
        console.log("[PIL-WS] Subscribed to:", message.channel);
        return;
      }

      if (message.type === "error") {
        console.error("[PIL-WS] Server error:", message.error);
        return;
      }

      // Handle channel data
      if (message.channel && message.data) {
        const handlers = this.handlers.get(message.channel as SubscriptionChannel);
        handlers?.forEach(handler => {
          try {
            handler(message.data);
          } catch (error) {
            console.error("[PIL-WS] Handler error:", error);
          }
        });
      }
    } catch (error) {
      console.error("[PIL-WS] Failed to parse message:", error);
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      this.send({ type: "ping" });
    }, this.config.heartbeatInterval);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
      console.error("[PIL-WS] Max reconnect attempts reached");
      return;
    }

    const delay = this.config.reconnectInterval * Math.pow(2, this.reconnectAttempts);
    console.log(`[PIL-WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts + 1})`);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connect().catch(console.error);
    }, delay);
  }

  private resubscribeAll(): void {
    const channels = new Set<SubscriptionChannel>();
    
    this.subscriptions.forEach(sub => {
      if (!channels.has(sub.channel)) {
        channels.add(sub.channel);
        this.sendSubscription(sub.channel, sub.params);
      }
    });
  }
}

// ============================================================================
// Exchange WebSocket Manager
// ============================================================================

export class ExchangeWSManager {
  private ws: PILExchangeWebSocket;
  private provider: ethers.Provider;

  constructor(
    wsUrl: string,
    provider: ethers.Provider
  ) {
    this.ws = new PILExchangeWebSocket({ url: wsUrl });
    this.provider = provider;
  }

  /**
   * Initialize WebSocket connection
   */
  async init(): Promise<void> {
    await this.ws.connect();
  }

  /**
   * Close connection
   */
  close(): void {
    this.ws.disconnect();
  }

  /**
   * Subscribe to trade updates for a pool
   */
  subscribeTrades(
    poolId: string,
    callback: (trade: TradeUpdate) => void
  ): () => void {
    const subId = this.ws.subscribe("trades", { poolId });
    
    this.ws.on("trades", (trade: TradeUpdate) => {
      if (!poolId || trade.poolId === poolId) {
        callback(trade);
      }
    });

    return () => this.ws.unsubscribe(subId);
  }

  /**
   * Subscribe to order book updates
   */
  subscribeOrders(
    pair: string,
    callback: (order: OrderUpdate) => void
  ): () => void {
    const subId = this.ws.subscribe("orders", { pair });
    
    this.ws.on("orders", (order: OrderUpdate) => {
      if (!pair || order.pair === pair) {
        callback(order);
      }
    });

    return () => this.ws.unsubscribe(subId);
  }

  /**
   * Subscribe to pool updates
   */
  subscribePools(
    callback: (pool: PoolUpdate) => void
  ): () => void {
    const subId = this.ws.subscribe("pools");
    this.ws.on("pools", callback);
    return () => this.ws.unsubscribe(subId);
  }

  /**
   * Subscribe to stealth address announcements
   */
  subscribeStealthAnnouncements(
    callback: (announcement: StealthAnnouncement) => void
  ): () => void {
    const subId = this.ws.subscribe("stealth");
    this.ws.on("stealth", callback);
    return () => this.ws.unsubscribe(subId);
  }

  /**
   * Subscribe to user-specific updates (requires auth)
   */
  subscribeUserUpdates(
    address: string,
    signature: string,
    callbacks: {
      onDeposit?: (data: any) => void;
      onWithdraw?: (data: any) => void;
      onOrder?: (order: OrderUpdate) => void;
      onFill?: (fill: any) => void;
    }
  ): () => void {
    const subId = this.ws.subscribe("user", { address, signature });
    
    // User channel sends different event types
    this.ws.on("user" as any, (data: any) => {
      switch (data.type) {
        case "deposit":
          callbacks.onDeposit?.(data);
          break;
        case "withdraw":
          callbacks.onWithdraw?.(data);
          break;
        case "order":
          callbacks.onOrder?.(data);
          break;
        case "fill":
          callbacks.onFill?.(data);
          break;
      }
    });

    return () => this.ws.unsubscribe(subId);
  }

  /**
   * Get WebSocket connection status
   */
  get connected(): boolean {
    return this.ws.isConnected;
  }
}

// ============================================================================
// React Hook (for frontend)
// ============================================================================

export function useExchangeWebSocket(wsUrl: string) {
  // This is a placeholder for React integration
  // In real implementation, use React hooks
  
  const connect = async () => {
    const manager = new ExchangeWSManager(
      wsUrl,
      new ethers.JsonRpcProvider()
    );
    await manager.init();
    return manager;
  };

  return { connect };
}

// ============================================================================
// Usage Example
// ============================================================================

/*
import { ExchangeWSManager } from './websocket';

async function main() {
  const manager = new ExchangeWSManager(
    'wss://api.pil.network/exchange/v1/ws',
    provider
  );

  await manager.init();

  // Subscribe to trades
  const unsubTrades = manager.subscribeTrades('0x...poolId', (trade) => {
    console.log('New trade:', trade);
  });

  // Subscribe to orders
  const unsubOrders = manager.subscribeOrders('ETH/USDC', (order) => {
    console.log('Order update:', order);
  });

  // Subscribe to stealth announcements
  const unsubStealth = manager.subscribeStealthAnnouncements((announcement) => {
    console.log('Stealth payment:', announcement);
  });

  // Later: cleanup
  unsubTrades();
  unsubOrders();
  unsubStealth();
  manager.close();
}
*/

export default PILExchangeWebSocket;
