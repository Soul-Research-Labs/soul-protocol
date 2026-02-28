/**
 * ZASEON Load Testing - Nullifier Stress Test
 * K6 load test for nullifier registry under extreme load
 * Author: ZASEON Team
 * Date: January 2026
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend, Gauge } from 'k6/metrics';
import { randomBytes } from 'k6/crypto';
import { SharedArray } from 'k6/data';

// Custom metrics
const nullifierChecks = new Counter('nullifier_checks');
const nullifierRegistrations = new Counter('nullifier_registrations');
const duplicateAttempts = new Counter('duplicate_attempts');
const checkLatency = new Trend('nullifier_check_latency', true);
const registerLatency = new Trend('nullifier_register_latency', true);
const collisionRate = new Rate('collision_rate');
const throughput = new Gauge('current_throughput');

// Pre-generated nullifiers for duplicate detection testing
const preGeneratedNullifiers = new SharedArray('nullifiers', function() {
  const nullifiers = [];
  for (let i = 0; i < 10000; i++) {
    nullifiers.push('0x' + Array(64).fill(0).map(() => 
      Math.floor(Math.random() * 16).toString(16)
    ).join(''));
  }
  return nullifiers;
});

// Test configuration
export const options = {
  scenarios: {
    // Normal load - check existing nullifiers
    check_existing: {
      executor: 'constant-arrival-rate',
      rate: 1000,           // 1000 RPS
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 500,
      maxVUs: 2000,
      exec: 'checkNullifier',
    },
    // High load - register new nullifiers
    register_new: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      stages: [
        { duration: '2m', target: 500 },
        { duration: '5m', target: 2000 },
        { duration: '5m', target: 5000 },
        { duration: '3m', target: 0 },
      ],
      preAllocatedVUs: 1000,
      maxVUs: 5000,
      exec: 'registerNullifier',
    },
    // Attack simulation - replay attacks
    replay_attack: {
      executor: 'per-vu-iterations',
      vus: 100,
      iterations: 100,
      startTime: '20m',
      exec: 'simulateReplayAttack',
    },
    // Collision test
    collision_test: {
      executor: 'shared-iterations',
      vus: 50,
      iterations: 10000,
      startTime: '25m',
      exec: 'testCollision',
    },
  },
  thresholds: {
    'nullifier_check_latency': ['p(95)<100', 'p(99)<500'],
    'nullifier_register_latency': ['p(95)<500', 'p(99)<2000'],
    'collision_rate': ['rate<0.001'], // Less than 0.1% collisions
    'http_req_failed': ['rate<0.01'],  // Less than 1% errors
  },
};

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8545';
const NULLIFIER_REGISTRY = __ENV.NULLIFIER_REGISTRY || '0x1234567890abcdef';

/**
 * Generate a random nullifier hash
 */
function generateNullifier() {
  const bytes = randomBytes(32);
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get a pre-generated nullifier (for collision testing)
 */
function getPreGeneratedNullifier() {
  const index = Math.floor(Math.random() * preGeneratedNullifiers.length);
  return preGeneratedNullifiers[index];
}

/**
 * Make RPC call
 */
function rpcCall(method, params) {
  const payload = JSON.stringify({
    jsonrpc: '2.0',
    method: 'eth_call',
    params: [{
      to: NULLIFIER_REGISTRY,
      data: encodeMethod(method, params),
    }, 'latest'],
    id: Date.now(),
  });

  return http.post(BASE_URL, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
  });
}

/**
 * Encode method call
 */
function encodeMethod(method, params) {
  // Simplified encoding
  const signatures = {
    isNullifierSpent: '0x12345678',
    registerNullifier: '0x87654321',
    getNullifierDomain: '0xabcdef12',
    verifyNullifier: '0x34567890',
  };
  return signatures[method] + (params[0] || '').slice(2);
}

/**
 * Check if nullifier exists
 */
export function checkNullifier() {
  const nullifier = getPreGeneratedNullifier();
  
  group('Nullifier Check', () => {
    const startTime = Date.now();
    const response = rpcCall('isNullifierSpent', [nullifier]);
    const latency = Date.now() - startTime;

    nullifierChecks.add(1);
    checkLatency.add(latency);

    check(response, {
      'status is 200': (r) => r.status === 200,
      'response is valid': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.result !== undefined;
        } catch {
          return false;
        }
      },
      'latency under 100ms': (r) => r.timings.duration < 100,
    });
  });

  sleep(0.01);
}

/**
 * Register new nullifier
 */
export function registerNullifier() {
  const nullifier = generateNullifier();
  
  group('Nullifier Registration', () => {
    const startTime = Date.now();
    const response = rpcCall('registerNullifier', [nullifier]);
    const latency = Date.now() - startTime;

    nullifierRegistrations.add(1);
    registerLatency.add(latency);

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'registration successful': (r) => {
        try {
          const body = JSON.parse(r.body);
          return !body.error;
        } catch {
          return false;
        }
      },
      'latency under 500ms': (r) => r.timings.duration < 500,
    });

    if (!success) {
      collisionRate.add(1);
    } else {
      collisionRate.add(0);
    }
  });

  sleep(0.05);
}

/**
 * Simulate replay attack
 */
export function simulateReplayAttack() {
  // Use same nullifier repeatedly
  const nullifier = preGeneratedNullifiers[__VU % 100];
  
  group('Replay Attack Simulation', () => {
    for (let i = 0; i < 10; i++) {
      const response = rpcCall('registerNullifier', [nullifier]);
      duplicateAttempts.add(1);

      // First attempt might succeed, subsequent should fail
      const rejected = check(response, {
        'duplicate rejected': (r) => {
          try {
            const body = JSON.parse(r.body);
            // Check if error indicates duplicate
            return body.error && body.error.message?.includes('already spent');
          } catch {
            return false;
          }
        },
      });

      sleep(0.1);
    }
  });
}

/**
 * Test for hash collisions
 */
export function testCollision() {
  const nullifier1 = generateNullifier();
  
  // Generate a "similar" nullifier (XOR last byte)
  const bytes = nullifier1.slice(2);
  const lastByte = parseInt(bytes.slice(-2), 16);
  const newLastByte = (lastByte ^ 0xFF).toString(16).padStart(2, '0');
  const nullifier2 = '0x' + bytes.slice(0, -2) + newLastByte;

  group('Collision Test', () => {
    // Register first nullifier
    const response1 = rpcCall('registerNullifier', [nullifier1]);
    
    // Try to register similar nullifier
    const response2 = rpcCall('registerNullifier', [nullifier2]);

    // Both should succeed (no collision)
    const noCollision = check([response1, response2], {
      'no collision detected': (responses) => {
        try {
          const body1 = JSON.parse(responses[0].body);
          const body2 = JSON.parse(responses[1].body);
          return !body1.error && !body2.error;
        } catch {
          return false;
        }
      },
    });

    if (!noCollision) {
      collisionRate.add(1);
    } else {
      collisionRate.add(0);
    }
  });

  sleep(0.1);
}

/**
 * Setup function
 */
export function setup() {
  console.log('Starting Zaseon Nullifier Stress Test');
  console.log(`Target: ${BASE_URL}`);
  console.log(`Registry: ${NULLIFIER_REGISTRY}`);
  console.log(`Pre-generated nullifiers: ${preGeneratedNullifiers.length}`);
  
  // Check connectivity
  const response = http.post(BASE_URL, JSON.stringify({
    jsonrpc: '2.0',
    method: 'eth_blockNumber',
    params: [],
    id: 1,
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  if (response.status !== 200) {
    console.warn('Warning: Cannot connect to RPC endpoint');
  }

  return { 
    startTime: Date.now(),
    preGeneratedCount: preGeneratedNullifiers.length,
  };
}

/**
 * Teardown function
 */
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`\nNullifier Stress Test completed in ${duration}s`);
}

/**
 * Custom summary handler
 */
export function handleSummary(data) {
  const summary = generateSummary(data);
  
  return {
    'reports/load_test_nullifier_stress.json': JSON.stringify(data, null, 2),
    'reports/nullifier_stress_summary.txt': summary,
    'stdout': summary,
  };
}

function generateSummary(data) {
  const m = data.metrics;
  
  let s = '\n' + '='.repeat(60) + '\n';
  s += '       Zaseon NULLIFIER STRESS TEST SUMMARY\n';
  s += '='.repeat(60) + '\n\n';
  
  s += '📊 OPERATIONS\n';
  s += `   Nullifier Checks:        ${m.nullifier_checks?.values?.count || 0}\n`;
  s += `   Nullifier Registrations: ${m.nullifier_registrations?.values?.count || 0}\n`;
  s += `   Duplicate Attempts:      ${m.duplicate_attempts?.values?.count || 0}\n\n`;
  
  s += '⏱️ LATENCY\n';
  s += `   Check p50:    ${m.nullifier_check_latency?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms\n`;
  s += `   Check p95:    ${m.nullifier_check_latency?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms\n`;
  s += `   Check p99:    ${m.nullifier_check_latency?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms\n`;
  s += `   Register p50: ${m.nullifier_register_latency?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms\n`;
  s += `   Register p95: ${m.nullifier_register_latency?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms\n`;
  s += `   Register p99: ${m.nullifier_register_latency?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms\n\n`;
  
  s += '🔒 SECURITY\n';
  s += `   Collision Rate: ${((m.collision_rate?.values?.rate || 0) * 100).toFixed(4)}%\n`;
  s += `   HTTP Failures:  ${((m.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%\n\n`;
  
  s += '📈 THROUGHPUT\n';
  const duration = (data.state?.testRunDurationMs || 1) / 1000;
  const totalOps = (m.nullifier_checks?.values?.count || 0) + (m.nullifier_registrations?.values?.count || 0);
  s += `   Operations/sec: ${(totalOps / duration).toFixed(2)}\n`;
  s += `   Total Duration: ${duration.toFixed(2)} s\n`;
  
  s += '\n' + '='.repeat(60) + '\n';
  
  return s;
}
