//! Capability management - raise/drop capabilities per operation.

use anyhow::{Context, Result};
use capctl::caps::{Cap, CapState};
use tracing::{debug, trace};

/// The capabilities we need for eBPF operations.
pub const REQUIRED_CAPS: &[Cap] = &[
    Cap::BPF,       // Load/unload eBPF programs
    Cap::PERFMON,   // Attach to perf events, kprobes
    Cap::NET_ADMIN, // XDP, TC programs
];

/// Guard that drops capabilities when it goes out of scope.
pub struct CapGuard {
    caps: Vec<Cap>,
}

impl Drop for CapGuard {
    fn drop(&mut self) {
        if let Err(e) = drop_caps(&self.caps) {
            tracing::error!("Failed to drop capabilities: {}", e);
        }
    }
}

/// Raise the specified capabilities into the effective set.
/// Returns a guard that will drop them when it goes out of scope.
pub fn raise_caps(caps: &[Cap]) -> Result<CapGuard> {
    let mut state = CapState::get_current().context("Failed to get current capabilities")?;

    for cap in caps {
        if !state.permitted.has(*cap) {
            anyhow::bail!(
                "Capability {:?} not in permitted set. Is the daemon running with AmbientCapabilities?",
                cap
            );
        }
        debug!("Raising capability: {:?}", cap);
        state.effective.add(*cap);
    }

    state
        .set_current()
        .context("Failed to set capabilities")?;

    trace!("Capabilities raised: {:?}", caps);

    Ok(CapGuard {
        caps: caps.to_vec(),
    })
}

/// Drop the specified capabilities from the effective set.
fn drop_caps(caps: &[Cap]) -> Result<()> {
    let mut state = CapState::get_current().context("Failed to get current capabilities")?;

    for cap in caps {
        debug!("Dropping capability: {:?}", cap);
        state.effective.drop(*cap);
    }

    state
        .set_current()
        .context("Failed to drop capabilities")?;

    trace!("Capabilities dropped: {:?}", caps);
    Ok(())
}

/// Check if we have the required capabilities in our permitted set.
pub fn check_permitted_caps() -> Result<Vec<String>> {
    let state = CapState::get_current().context("Failed to get current capabilities")?;

    let mut available = Vec::new();
    let mut missing = Vec::new();

    for cap in REQUIRED_CAPS {
        if state.permitted.has(*cap) {
            available.push(format!("{:?}", cap));
        } else {
            missing.push(format!("{:?}", cap));
        }
    }

    if !missing.is_empty() {
        tracing::warn!("Missing capabilities in permitted set: {:?}", missing);
    }

    Ok(available)
}

/// Execute a closure with the specified capabilities raised.
/// Capabilities are automatically dropped after the closure returns.
pub fn with_caps<T, F>(caps: &[Cap], f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let _guard = raise_caps(caps)?;
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_permitted_caps() {
        // This will likely show no caps in a test environment
        let result = check_permitted_caps();
        assert!(result.is_ok());
    }
}
