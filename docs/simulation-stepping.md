# Simulation Stepping & Debugger-Safe Time Control

## Overview

The vm-devices crate provides a simulation controller that gives external tools
(dSPACE, Simulink, CARLA, or a debugger) full control over time inside a guest VM.
The guest's perception of time — both wall clock and monotonic clock — can be
frozen, stepped, or advanced at any rate.

## How the Guest Gets Time

The guest VM gets its time from two independent sources:

**Wall clock** (`CLOCK_REALTIME`) — read from vtime shared memory registers.
The host writes `mono_ns` and `wall_offset_ns` to a 128-byte ivshmem region.
The guest kernel driver (`vtime.ko`) reads via MMIO, and the `vtime-sync`
daemon disciplines the local system clock.

**Monotonic clock** (`CLOCK_MONOTONIC`) — driven by the CPU's hardware timer
(TSC on x86, architected timer on ARM). Cannot be written to directly, but
halting the vCPU via QEMU's QMP protocol stops the timer.

## SimController API

```rust
use vm_devices::clock::simulation::{SimController, SimulationClock};
use vm_devices::qmp::QmpClient;

// Create a simulation clock starting at 1 second, with a wall offset
let clock = Arc::new(SimulationClock::new(1_000_000_000, wall_offset));

// Connect to QEMU's QMP socket
let qmp = QmpClient::connect("/tmp/vm-svc-vm1-qmp.sock")?;

// Create controller: 100ms steps, with QMP for vCPU control
let ctrl = SimController::with_qmp(clock.clone(), 100_000_000, qmp);
```

### Operations

| Method | Effect |
|--------|--------|
| `ctrl.step()` | Advance vtime by one step delta. Device sims update shared memory. Guest reads new time on next access. |
| `ctrl.step_n(N)` | Advance by N steps. |
| `ctrl.pause()` | QMP `stop` → all vCPUs halt. `CLOCK_MONOTONIC` stops. vtime registers frozen. |
| `ctrl.resume(0)` | QMP `cont` → vCPUs resume. Guest sees no time jump. |
| `ctrl.resume(N)` | Advance vtime by N ns, then resume. Guest sees controlled time jump. |
| `ctrl.is_running()` | Query if guest vCPUs are currently running. |
| `ctrl.now_ns()` | Current simulation monotonic time. |

## Use Cases

### Debugger Stepping Across RT↔HP Boundary

When the real-time side hits a breakpoint:

```
1. ctrl.pause()        # Guest halts — CLOCK_MONOTONIC frozen
                       # No timeouts expire, no watchdogs fire
2. Debug RT code       # Take as long as needed
3. ctrl.resume(0)      # Guest resumes, unaware it was paused
```

### Deterministic Co-Simulation

External simulation tool drives time:

```
loop {
    simulation_tool.compute_next_step()

    // Inject CAN frames, sensor values, etc. into shared memory
    can_bridge.rx_write(&frame)
    health_sim.update_sensors(tick)

    // Advance guest time by exactly one step
    ctrl.step()

    // Read back guest outputs (CAN TX, diagnostic responses)
    if let Some(frame) = can_bridge.tx_read() { ... }
}
```

All virtual devices update in lockstep. No real-time drift, no race conditions.

### Fast-Forward Testing

```
ctrl.step_n(10_000)   // Advance 1000 seconds in milliseconds
                       // Useful for soak tests, certificate expiry,
                       // aging scenarios
```

## Architecture

```
External Tool (dSPACE / Simulink / Debugger)
    │
    ▼
SimController
    ├── SimulationClock (AtomicU64 + Condvar)
    │     │
    │     └── read by device simulators:
    │           ├── TimeSim  → ivshmem "time"  (128 bytes)
    │           ├── HealthSim → ivshmem "health" (4 KB)
    │           └── CanBridge → ivshmem "can0"  (1 MB)
    │                              │
    │                              ▼
    │                        Guest VM kernel drivers
    │                        (vtime, vhealth, vcan-shm)
    │
    └── QmpClient (JSON over Unix socket)
          │
          └── QEMU: stop/cont vCPUs
                └── CLOCK_MONOTONIC frozen when stopped
```

## Time Latency

| Path | Latency |
|------|---------|
| Host shm write → guest MMIO read | ~100 ns (cache-line coherency) |
| Simulation step → guest sees new time | 1 step (deterministic, zero jitter) |
| QMP stop → vCPU halted | ~1 ms (QEMU scheduling) |
| QMP cont → vCPU running | ~1 ms |

## What Each Clock Affects

| Guest C call | Clock used | Controlled by vtime? | Controlled by QMP pause? |
|-------------|------------|---------------------|-------------------------|
| `sleep()` / `nanosleep()` | CLOCK_MONOTONIC | No | **Yes** (vCPU halted) |
| `select()` / `poll()` / `epoll_wait()` | CLOCK_MONOTONIC | No | **Yes** |
| `clock_gettime(CLOCK_REALTIME)` | CLOCK_REALTIME | **Yes** (vtime-sync) | **Yes** |
| `clock_gettime(CLOCK_MONOTONIC)` | CLOCK_MONOTONIC | No | **Yes** |
| `timerfd_create(CLOCK_REALTIME)` | CLOCK_REALTIME | **Yes** | **Yes** |
| `pthread_cond_timedwait()` | CLOCK_REALTIME (default) | **Yes** | **Yes** |

**Key insight**: QMP pause halts everything (both clocks). vtime only affects
wall clock. For full time control, use both together.

## Device Simulator Integration

Device simulators can run in two modes:

**Real-time mode** (default): `sim.run(&cancel)` — uses `thread::sleep()`,
reads from `SystemClock`. For normal operation.

**Stepped mode**: call `sim.update_time()` / `sim.update_sensors(tick)`
directly after each `controller.step()`. Or spawn sim threads that call
`clock.wait_tick()` to block between steps:

```rust
// Threaded stepped mode
let clock = controller.clock();
std::thread::spawn(move || {
    let sim = TimeSim::new(shm, doorbell, clock.clone());
    sim.init();
    loop {
        clock.wait_tick();                // blocks until controller steps
        sim.update_time();                // write new time to shm
    }
});
```

## QMP Socket Location

QEMU is launched with:
```
-qmp unix:/tmp/vm-svc-{vm_name}-qmp.sock,server,nowait
```

The socket is created automatically. Connect after QEMU starts.

## Integration Guide for Simulation Teams

To control a VM from an external simulation tool:

1. **Start the vehicle stack** — `vm-service` launches each VM's QEMU with its QMP socket
2. **Connect QMP**: `QmpClient::connect("/tmp/vm-svc-vm1-qmp.sock")`
3. **Create SimController** with the desired step size
4. **Replace device clocks**: pass `controller.clock()` to TimeSim, HealthSim, CanBridge
5. **Drive the loop**: call `step()` at the simulation tick rate
6. **For debug sessions**: `pause()` / `resume(0)`

The vm-devices crate is open source: `github.com/skarlsson/sumo-machine-manager`

## Test Coverage

32 automated tests verify:
- Time frozen between steps (no drift)
- Exact step advancement (configurable delta)
- Wall offset independently controllable (gPTP simulation)
- Coordinated time+health on shared clock
- Threaded sim loops block until controller steps
- Deterministic sensor values at same tick number
