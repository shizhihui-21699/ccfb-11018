/**
 * In-memory transports for tests and the CLI demo.
 *
 * A transport is a pair of byte queues.  `loopbackTransport` wires the host to
 * a `SimulatedDevice` through a small responder that routes the first flight to
 * `handleHello` and the next to `handleConfirm`.  Keeping the responder separate
 * means the host orchestrator stays transport-agnostic (the same code would run
 * over WebUSB).
 */

import type { DeviceTransport } from "../manager/verify.ts";
import type { Bytes } from "../util/bytes.ts";
import { canonicalString } from "../util/canonical.ts";
import { encodeAttest, encodeReady, type AttestMessage, type ReadyMessage } from "../protocol/messages.ts";
import type { SimulatedDevice } from "../device/simulator.ts";

/** A device that responds to at most two flights (HELLO, then CONFIRM). */
export interface DeviceResponder {
  respond(bytes: Bytes, flight: number): Promise<Bytes>;
}

/** Wrap a simulated device into a responder that tracks the flight index. */
export function simulatedResponder(device: SimulatedDevice): DeviceResponder {
  let flight = 0;
  return {
    async respond(bytes) {
      if (flight === 0) {
        flight = 1;
        const attest: AttestMessage = await device.handleHello(bytes);
        return encodeAttest(attest);
      }
      if (flight === 1) {
        flight = 2;
        const ready: ReadyMessage = await device.handleConfirm(bytes);
        return encodeReady(ready);
      }
      throw new Error("responder: unexpected extra flight");
    },
  };
}

interface Channel {
  push(b: Bytes): void;
  next(): Promise<Bytes>;
}

function makeChannel(cap = 1 << 20): Channel {
  const queue: Bytes[] = [];
  let waiter: ((b: Bytes) => void) | null = null;
  return {
    push(b) {
      if (b.length > cap) throw new Error("channel: message too large");
      if (waiter) {
        const w = waiter;
        waiter = null;
        w(b);
      } else {
        queue.push(b);
      }
    },
    async next() {
      const q = queue.shift();
      if (q) return q;
      return new Promise<Bytes>((resolve) => {
        waiter = resolve;
      });
    },
  };
}

export type WireTap = (direction: "host->device" | "device->host", bytes: Bytes) => Bytes;

/**
 * Connect the host to a responder.
 *
 * `tap` may rewrite bytes in either direction — used by relay tests and by
 * "corrupting middlebox" tests.  If `tap` throws, the flight is dropped (the
 * host sees a timeout / transport error).
 */
export function loopbackTransport(responder: DeviceResponder, tap?: WireTap): DeviceTransport {
  const hostToDev = makeChannel();
  const devToHost = makeChannel();
  let flight = 0;
  let pumpRunning = false;

  async function pump(): Promise<void> {
    if (pumpRunning) return;
    pumpRunning = true;
    try {
      for (;;) {
        const fromHost = await hostToDev.next();
        let wire = fromHost;
        if (tap) wire = tap("host->device", fromHost);
        let response: Bytes;
        try {
          response = await responder.respond(wire, flight);
        } catch {
          // Device refused this flight; drop it so the host times out/errors.
          return;
        }
        flight++;
        devToHost.push(tap ? tap("device->host", response) : response);
      }
    } finally {
      pumpRunning = false;
    }
  }

  return {
    async send(bytes) {
      void pump();
      hostToDev.push(bytes);
    },
    receive: () => devToHost.next(),
  };
}

/** Helper to round-trip a JSON message through canonical encoding. */
export function canon(v: unknown): Bytes {
  return new TextEncoder().encode(canonicalString(v));
}

export { encodeAttest, encodeReady };
