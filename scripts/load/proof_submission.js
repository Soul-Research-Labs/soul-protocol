/**
 * ZASEON Load Testing - Proof Submission
 * K6 load test for high-concurrency proof submissions
 * Author: ZASEON Team
 * Date: January 2026
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import { randomBytes } from "k6/crypto";

// Custom metrics
const proofSubmissions = new Counter("proof_submissions");
const successfulProofs = new Counter("successful_proofs");
const failedProofs = new Counter("failed_proofs");
const proofLatency = new Trend("proof_latency", true);
const successRate = new Rate("success_rate");

// Test configuration
export const options = {
  scenarios: {
    // Ramp up to 10,000 VUs
    stress_test: {
      executor: "ramping-vus",
      startVUs: 100,
      stages: [
        { duration: "2m", target: 1000 }, // Ramp to 1000
        { duration: "5m", target: 5000 }, // Ramp to 5000
        { duration: "10m", target: 10000 }, // Ramp to 10000
        { duration: "10m", target: 10000 }, // Hold at 10000
        { duration: "3m", target: 0 }, // Ramp down
      ],
    },
    // Sustained load test
    sustained_load: {
      executor: "constant-vus",
      vus: 5000,
      duration: "30m",
      startTime: "30m", // Start after stress test
    },
    // Spike test
    spike_test: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "10s", target: 10000 }, // Instant spike
        { duration: "1m", target: 10000 }, // Hold
        { duration: "10s", target: 0 }, // Instant drop
      ],
      startTime: "65m",
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<2000", "p(99)<5000"], // 95% under 2s
    success_rate: ["rate>0.99"], // 99% success
    proof_latency: ["p(95)<3000"], // Proof processing
  },
};

// Configuration
const BASE_URL = __ENV.BASE_URL || "http://localhost:8545";
const CONTRACT_ADDRESS =
  __ENV.CONTRACT || "0x40eaa5de0c6497c8943c967b42799cb092c26adc";

/**
 * Generate a random proof hash
 */
function generateProofHash() {
  const bytes = randomBytes(32);
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

/**
 * Generate mock proof data
 */
function generateProofData() {
  return {
    proofHash: generateProofHash(),
    proofData:
      "0x" +
      randomBytes(256)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    publicInputs:
      "0x" +
      randomBytes(64)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    blockNumber: Math.floor(Date.now() / 1000),
  };
}

/**
 * Submit proof via JSON-RPC
 */
function submitProof(proof) {
  const payload = JSON.stringify({
    jsonrpc: "2.0",
    method: "eth_call",
    params: [
      {
        to: CONTRACT_ADDRESS,
        data: encodeProofSubmission(proof),
      },
      "latest",
    ],
    id: Date.now(),
  });

  const params = {
    headers: {
      "Content-Type": "application/json",
    },
    timeout: "30s",
  };

  const startTime = Date.now();
  const response = http.post(BASE_URL, payload, params);
  const latency = Date.now() - startTime;

  proofSubmissions.add(1);
  proofLatency.add(latency);

  return response;
}

/**
 * Encode proof submission call data
 */
function encodeProofSubmission(proof) {
  // Function signature: relayProof(bytes32,bytes,bytes,uint256)
  // keccak256 selector: cast sig "relayProof(bytes32,bytes,bytes,uint256)"
  const signature = "0x79d8c928";
  return signature + proof.proofHash.slice(2);
}

/**
 * Main test function
 */
export default function () {
  group("Proof Submission Load Test", () => {
    // Generate random proof
    const proof = generateProofData();

    // Submit proof
    const response = submitProof(proof);

    // Check response
    const success = check(response, {
      "status is 200": (r) => r.status === 200,
      "response has result": (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.result !== undefined || body.error === undefined;
        } catch {
          return false;
        }
      },
      "latency under 2s": (r) => r.timings.duration < 2000,
    });

    if (success) {
      successfulProofs.add(1);
      successRate.add(1);
    } else {
      failedProofs.add(1);
      successRate.add(0);
    }

    // Small delay between requests
    sleep(0.1);
  });
}

/**
 * Setup function - runs once before test
 */
export function setup() {
  console.log("Starting Zaseon Proof Submission Load Test");
  console.log(`Target: ${BASE_URL}`);
  console.log(`Contract: ${CONTRACT_ADDRESS}`);

  // Verify connectivity
  const response = http.post(
    BASE_URL,
    JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_chainId",
      params: [],
      id: 1,
    }),
    {
      headers: { "Content-Type": "application/json" },
    },
  );

  if (response.status !== 200) {
    throw new Error("Cannot connect to RPC endpoint");
  }

  const chainId = JSON.parse(response.body).result;
  console.log(`Connected to chain: ${chainId}`);

  return { chainId };
}

/**
 * Teardown function - runs once after test
 */
export function teardown(data) {
  console.log("Load test completed");
  console.log(`Chain ID: ${data.chainId}`);
}

/**
 * Handle test summary
 */
export function handleSummary(data) {
  return {
    "reports/load_test_proof_submission.json": JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: "  ", enableColors: true }),
  };
}

function textSummary(data, options) {
  const metrics = data.metrics;

  let summary = "\n=== Zaseon Proof Submission Load Test Summary ===\n\n";

  summary += `Total Proof Submissions: ${metrics.proof_submissions?.values?.count || 0}\n`;
  summary += `Successful Proofs: ${metrics.successful_proofs?.values?.count || 0}\n`;
  summary += `Failed Proofs: ${metrics.failed_proofs?.values?.count || 0}\n`;
  summary += `Success Rate: ${((metrics.success_rate?.values?.rate || 0) * 100).toFixed(2)}%\n\n`;

  summary += `Proof Latency (p95): ${metrics.proof_latency?.values?.["p(95)"]?.toFixed(2) || "N/A"} ms\n`;
  summary += `HTTP Duration (p95): ${metrics.http_req_duration?.values?.["p(95)"]?.toFixed(2) || "N/A"} ms\n\n`;

  summary += `Peak VUs: ${data.root_group?.checks?.length || "N/A"}\n`;
  summary += `Test Duration: ${data.state?.testRunDurationMs / 1000 || "N/A"} s\n`;

  return summary;
}
