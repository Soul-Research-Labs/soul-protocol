import React from "react";
import { renderHook, act } from "@testing-library/react-hooks";
import {
  SoulProvider,
  useSoul,
  useContainer,
  useContainers,
  useCreateContainer,
  useConsumeContainer,
  useNullifier,
  useVerifyPolicy,
  useTransaction,
  useGasEstimate,
} from "../hooks";

// ═════════════════════════════════════════════════════════════
//  Helper: Wrapper with SoulProvider
// ═════════════════════════════════════════════════════════════

function createWrapper(config = {}) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(SoulProvider, { config, children });
  };
}

// ═════════════════════════════════════════════════════════════
//  useSoul
// ═════════════════════════════════════════════════════════════

describe("useSoul", () => {
  it("throws when used outside SoulProvider", () => {
    const { result } = renderHook(() => useSoul());
    expect(result.error).toBeDefined();
    expect(result.error?.message).toContain(
      "useSoul must be used within a SoulProvider",
    );
  });

  it("returns default disconnected state", () => {
    const { result } = renderHook(() => useSoul(), {
      wrapper: createWrapper(),
    });

    expect(result.current.isConnected).toBe(false);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.client).toBeNull();
    expect(result.current.address).toBeNull();
    expect(result.current.chainId).toBeNull();
    expect(result.current.error).toBeNull();
    expect(typeof result.current.connect).toBe("function");
    expect(typeof result.current.disconnect).toBe("function");
  });

  it("connect fails when no wallet detected", async () => {
    // window.ethereum is undefined by default in jsdom
    const { result } = renderHook(() => useSoul(), {
      wrapper: createWrapper(),
    });

    await act(async () => {
      await result.current.connect();
    });

    expect(result.current.isConnected).toBe(false);
    expect(result.current.error).toBeDefined();
    expect(result.current.error?.message).toContain("No wallet detected");
  });
});

// ═════════════════════════════════════════════════════════════
//  useContainer
// ═════════════════════════════════════════════════════════════

describe("useContainer", () => {
  it("returns null container when not connected", () => {
    const { result } = renderHook(() => useContainer("0xabc"), {
      wrapper: createWrapper(),
    });

    expect(result.current.container).toBeNull();
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(typeof result.current.refetch).toBe("function");
  });

  it("returns null when containerId is undefined", () => {
    const { result } = renderHook(() => useContainer(undefined), {
      wrapper: createWrapper(),
    });

    expect(result.current.container).toBeNull();
  });

  it("respects enabled=false option", () => {
    const { result } = renderHook(
      () => useContainer("0xabc", { enabled: false }),
      { wrapper: createWrapper() },
    );

    expect(result.current.container).toBeNull();
    expect(result.current.isLoading).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════
//  useContainers
// ═════════════════════════════════════════════════════════════

describe("useContainers", () => {
  it("returns empty arrays when not connected", () => {
    const { result } = renderHook(() => useContainers(), {
      wrapper: createWrapper(),
    });

    expect(result.current.containers).toEqual([]);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.hasMore).toBe(true);
    expect(typeof result.current.loadMore).toBe("function");
    expect(typeof result.current.refetch).toBe("function");
  });

  it("accepts options", () => {
    const { result } = renderHook(
      () => useContainers({ limit: 5, offset: 10 }),
      { wrapper: createWrapper() },
    );

    expect(result.current.containers).toEqual([]);
  });
});

// ═════════════════════════════════════════════════════════════
//  useCreateContainer
// ═════════════════════════════════════════════════════════════

describe("useCreateContainer", () => {
  it("returns initial state", () => {
    const { result } = renderHook(() => useCreateContainer(), {
      wrapper: createWrapper(),
    });

    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(result.current.containerId).toBeNull();
    expect(result.current.txHash).toBeNull();
    expect(typeof result.current.createContainer).toBe("function");
    expect(typeof result.current.reset).toBe("function");
  });

  it("throws when not connected and createContainer is called", async () => {
    const { result } = renderHook(() => useCreateContainer(), {
      wrapper: createWrapper(),
    });

    await expect(
      act(async () => {
        await result.current.createContainer({
          proof: new Uint8Array([1, 2, 3]),
          publicInputs: ["0x1"],
        });
      }),
    ).rejects.toThrow("Not connected");
  });

  it("reset clears state", () => {
    const { result } = renderHook(() => useCreateContainer(), {
      wrapper: createWrapper(),
    });

    act(() => {
      result.current.reset();
    });

    expect(result.current.containerId).toBeNull();
    expect(result.current.txHash).toBeNull();
    expect(result.current.error).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════
//  useConsumeContainer
// ═════════════════════════════════════════════════════════════

describe("useConsumeContainer", () => {
  it("returns initial state", () => {
    const { result } = renderHook(() => useConsumeContainer(), {
      wrapper: createWrapper(),
    });

    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(result.current.txHash).toBeNull();
    expect(typeof result.current.consumeContainer).toBe("function");
    expect(typeof result.current.reset).toBe("function");
  });

  it("throws when not connected", async () => {
    const { result } = renderHook(() => useConsumeContainer(), {
      wrapper: createWrapper(),
    });

    await expect(
      act(async () => {
        await result.current.consumeContainer("0xabc");
      }),
    ).rejects.toThrow("Not connected");
  });
});

// ═════════════════════════════════════════════════════════════
//  useNullifier
// ═════════════════════════════════════════════════════════════

describe("useNullifier", () => {
  it("returns initial unspent state", () => {
    const { result } = renderHook(() => useNullifier("0xnull", "ethereum"), {
      wrapper: createWrapper(),
    });

    expect(result.current.isSpent).toBeNull();
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(typeof result.current.refetch).toBe("function");
  });

  it("handles undefined nullifier gracefully", () => {
    const { result } = renderHook(() => useNullifier(undefined, "ethereum"), {
      wrapper: createWrapper(),
    });

    expect(result.current.isSpent).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════
//  useVerifyPolicy
// ═════════════════════════════════════════════════════════════

describe("useVerifyPolicy", () => {
  it("returns initial state", () => {
    const { result } = renderHook(() => useVerifyPolicy(), {
      wrapper: createWrapper(),
    });

    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(result.current.result).toBeNull();
    expect(typeof result.current.verify).toBe("function");
    expect(typeof result.current.reset).toBe("function");
  });

  it("throws when not connected", async () => {
    const { result } = renderHook(() => useVerifyPolicy(), {
      wrapper: createWrapper(),
    });

    await expect(
      act(async () => {
        await result.current.verify(new Uint8Array([1]), "policy-1");
      }),
    ).rejects.toThrow("Not connected");
  });

  it("reset clears result", () => {
    const { result } = renderHook(() => useVerifyPolicy(), {
      wrapper: createWrapper(),
    });

    act(() => {
      result.current.reset();
    });

    expect(result.current.result).toBeNull();
    expect(result.current.error).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════
//  useTransaction
// ═════════════════════════════════════════════════════════════

describe("useTransaction", () => {
  it("returns idle state when no txHash", () => {
    const { result } = renderHook(() => useTransaction(null), {
      wrapper: createWrapper(),
    });

    expect(result.current.status).toBe("idle");
    expect(result.current.txHash).toBeNull();
    expect(result.current.error).toBeNull();
    expect(result.current.confirmations).toBe(0);
    expect(typeof result.current.reset).toBe("function");
  });

  it("reset returns to idle", () => {
    const { result } = renderHook(() => useTransaction("0xtx1"), {
      wrapper: createWrapper(),
    });

    act(() => {
      result.current.reset();
    });

    expect(result.current.status).toBe("idle");
    expect(result.current.confirmations).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════
//  useGasEstimate
// ═════════════════════════════════════════════════════════════

describe("useGasEstimate", () => {
  it("returns null estimate when not connected", () => {
    const { result } = renderHook(() => useGasEstimate("createContainer", []), {
      wrapper: createWrapper(),
    });

    expect(result.current.estimate).toBeNull();
    expect(result.current.estimateUSD).toBeNull();
    expect(result.current.isLoading).toBe(false);
    expect(typeof result.current.refetch).toBe("function");
  });
});
