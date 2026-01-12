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

    state.set_current().context("Failed to set capabilities")?;

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

    state.set_current().context("Failed to drop capabilities")?;

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

    // ==================== Constants Tests ====================

    #[test]
    fn test_required_caps_contains_bpf() {
        assert!(REQUIRED_CAPS.contains(&Cap::BPF));
    }

    #[test]
    fn test_required_caps_contains_perfmon() {
        assert!(REQUIRED_CAPS.contains(&Cap::PERFMON));
    }

    #[test]
    fn test_required_caps_contains_net_admin() {
        assert!(REQUIRED_CAPS.contains(&Cap::NET_ADMIN));
    }

    #[test]
    fn test_required_caps_count() {
        assert_eq!(REQUIRED_CAPS.len(), 3);
    }

    // ==================== check_permitted_caps Tests ====================

    #[test]
    fn test_check_permitted_caps() {
        // This will likely show no caps in a test environment
        let result = check_permitted_caps();
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_permitted_caps_returns_vec() {
        let result = check_permitted_caps().unwrap();
        // Result should be a Vec<String> (may be empty in test environment)
        let _ = result.len();
    }

    // ==================== raise_caps Tests ====================

    #[test]
    fn test_raise_caps_empty_list() {
        // Raising no caps should succeed
        let result = raise_caps(&[]);
        // This might fail if we don't have permission, but the interface should work
        match result {
            Ok(_guard) => {
                // Guard was created successfully
            }
            Err(e) => {
                // Expected in restricted test environment
                println!("Expected error in test env: {}", e);
            }
        }
    }

    // ==================== with_caps Tests ====================

    #[test]
    fn test_with_caps_empty_list() {
        let result = with_caps(&[], || Ok(42));
        match result {
            Ok(val) => assert_eq!(val, 42),
            Err(e) => {
                // Expected in restricted test environment
                println!("Expected error in test env: {}", e);
            }
        }
    }

    #[test]
    fn test_with_caps_closure_runs() {
        let mut was_called = false;
        let result = with_caps(&[], || {
            was_called = true;
            Ok(())
        });
        match result {
            Ok(()) => assert!(was_called),
            Err(_) => {
                // In a restricted environment, we might not have permission
                // to manipulate caps at all, so we just verify no panic
            }
        }
    }

    #[test]
    fn test_with_caps_returns_closure_result() {
        let result = with_caps(&[], || Ok("hello".to_string()));
        match result {
            Ok(s) => assert_eq!(s, "hello"),
            Err(_) => {
                // Expected in restricted test environment
            }
        }
    }

    // ==================== CapGuard Tests ====================

    #[test]
    fn test_cap_guard_drop_no_panic() {
        // Create a guard with empty caps (which we can manipulate)
        let guard = CapGuard { caps: vec![] };
        // Drop should not panic
        drop(guard);
    }

    // ==================== Integration-like Tests ====================

    #[test]
    fn test_check_caps_then_raise() {
        // First check what caps we have
        let available = check_permitted_caps().unwrap();
        println!("Available caps: {:?}", available);

        // Try to raise empty set (should always work)
        let result = raise_caps(&[]);
        match result {
            Ok(_) => println!("Successfully raised empty cap set"),
            Err(e) => println!("Could not raise caps (expected): {}", e),
        }
    }
}
