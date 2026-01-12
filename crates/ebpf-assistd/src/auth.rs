//! Polkit authentication module.
//!
//! Provides authorization checks via polkit D-Bus interface.
//! Caches authorization results for a configurable duration.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::{debug, info};
use zbus::Connection;

/// Default authorization cache duration (15 minutes, like sudo).
const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(15 * 60);

/// Polkit action IDs for ebpf-assist operations.
pub mod actions {
    pub const MANAGE: &str = "org.ebpf-assist.manage";
    pub const LOAD: &str = "org.ebpf-assist.load";
    pub const ATTACH: &str = "org.ebpf-assist.attach";
}

/// Result of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// User is authorized.
    Authorized,
    /// User is not authorized.
    NotAuthorized,
    /// Authorization challenge needed (GUI prompt).
    Challenge,
}

/// Cached authorization entry.
struct CacheEntry {
    result: AuthResult,
    expires: Instant,
}

/// Authorization manager with caching.
pub struct AuthManager {
    /// D-Bus connection (lazy initialized).
    connection: Option<Connection>,
    /// Cache of authorization results per (uid, action).
    cache: Arc<RwLock<HashMap<(u32, String), CacheEntry>>>,
    /// Cache duration.
    cache_duration: Duration,
    /// Whether polkit is enabled.
    enabled: bool,
}

impl AuthManager {
    /// Create a new auth manager.
    pub fn new() -> Self {
        Self {
            connection: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_duration: DEFAULT_CACHE_DURATION,
            enabled: true,
        }
    }

    /// Create a disabled auth manager (for testing or when running as root).
    pub fn disabled() -> Self {
        Self {
            connection: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_duration: DEFAULT_CACHE_DURATION,
            enabled: false,
        }
    }

    /// Set the cache duration.
    pub fn with_cache_duration(mut self, duration: Duration) -> Self {
        self.cache_duration = duration;
        self
    }

    /// Check if the user is authorized for an action.
    /// Returns immediately if cached, otherwise queries polkit.
    pub async fn check_authorization(&mut self, uid: u32, action: &str) -> Result<AuthResult> {
        if !self.enabled {
            debug!("Auth disabled, allowing action: {}", action);
            return Ok(AuthResult::Authorized);
        }

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&(uid, action.to_string())) {
                if entry.expires > Instant::now() {
                    debug!(
                        "Auth cache hit for uid={} action={}: {:?}",
                        uid, action, entry.result
                    );
                    return Ok(entry.result);
                }
            }
        }

        // Query polkit
        let result = self.query_polkit(uid, action).await?;

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                (uid, action.to_string()),
                CacheEntry {
                    result,
                    expires: Instant::now() + self.cache_duration,
                },
            );
        }

        info!(
            "Auth result for uid={} action={}: {:?}",
            uid, action, result
        );
        Ok(result)
    }

    /// Request authorization with user interaction (GUI prompt).
    pub async fn request_authorization(&mut self, uid: u32, action: &str) -> Result<AuthResult> {
        if !self.enabled {
            return Ok(AuthResult::Authorized);
        }

        let result = self.query_polkit_interactive(uid, action).await?;

        // Cache successful authorizations
        if result == AuthResult::Authorized {
            let mut cache = self.cache.write().await;
            cache.insert(
                (uid, action.to_string()),
                CacheEntry {
                    result,
                    expires: Instant::now() + self.cache_duration,
                },
            );
        }

        Ok(result)
    }

    /// Clear the authorization cache for a user.
    pub async fn clear_cache(&self, uid: Option<u32>) {
        let mut cache = self.cache.write().await;
        if let Some(uid) = uid {
            cache.retain(|(cached_uid, _), _| *cached_uid != uid);
            info!("Cleared auth cache for uid={}", uid);
        } else {
            cache.clear();
            info!("Cleared all auth cache");
        }
    }

    /// Get or create the D-Bus connection.
    async fn get_connection(&mut self) -> Result<&Connection> {
        if self.connection.is_none() {
            debug!("Connecting to system D-Bus");
            let conn = Connection::system()
                .await
                .context("Failed to connect to system D-Bus")?;
            self.connection = Some(conn);
        }
        Ok(self.connection.as_ref().unwrap())
    }

    /// Query polkit without user interaction.
    async fn query_polkit(&mut self, uid: u32, action: &str) -> Result<AuthResult> {
        let conn = self.get_connection().await?;

        // Call org.freedesktop.PolicyKit1.Authority.CheckAuthorization
        let reply: (bool, bool, HashMap<String, String>) = conn
            .call_method(
                Some("org.freedesktop.PolicyKit1"),
                "/org/freedesktop/PolicyKit1/Authority",
                Some("org.freedesktop.PolicyKit1.Authority"),
                "CheckAuthorization",
                // Subject: Unix process
                &(
                    "unix-process",
                    vec![
                        ("pid", zbus::zvariant::Value::U32(std::process::id())),
                        ("uid", zbus::zvariant::Value::U32(uid)),
                        ("start-time", zbus::zvariant::Value::U64(0)),
                    ]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
                    action,
                    HashMap::<String, String>::new(), // details
                    0u32,                             // flags: 0 = don't allow user interaction
                    "",                               // cancellation_id
                ),
            )
            .await
            .context("Failed to call CheckAuthorization")?
            .body()
            .deserialize()
            .context("Failed to parse CheckAuthorization response")?;

        let (is_authorized, is_challenge, _details) = reply;

        if is_authorized {
            Ok(AuthResult::Authorized)
        } else if is_challenge {
            Ok(AuthResult::Challenge)
        } else {
            Ok(AuthResult::NotAuthorized)
        }
    }

    /// Query polkit with user interaction (shows GUI prompt).
    async fn query_polkit_interactive(&mut self, uid: u32, action: &str) -> Result<AuthResult> {
        let conn = self.get_connection().await?;

        // Call with AllowUserInteraction flag (0x1)
        let reply: (bool, bool, HashMap<String, String>) = conn
            .call_method(
                Some("org.freedesktop.PolicyKit1"),
                "/org/freedesktop/PolicyKit1/Authority",
                Some("org.freedesktop.PolicyKit1.Authority"),
                "CheckAuthorization",
                &(
                    "unix-process",
                    vec![
                        ("pid", zbus::zvariant::Value::U32(std::process::id())),
                        ("uid", zbus::zvariant::Value::U32(uid)),
                        ("start-time", zbus::zvariant::Value::U64(0)),
                    ]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
                    action,
                    HashMap::<String, String>::new(),
                    1u32, // flags: AllowUserInteraction
                    "",
                ),
            )
            .await
            .context("Failed to call CheckAuthorization (interactive)")?
            .body()
            .deserialize()
            .context("Failed to parse CheckAuthorization response")?;

        let (is_authorized, _is_challenge, _details) = reply;

        if is_authorized {
            Ok(AuthResult::Authorized)
        } else {
            Ok(AuthResult::NotAuthorized)
        }
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== AuthResult Tests ====================

    #[test]
    fn test_auth_result_equality() {
        assert_eq!(AuthResult::Authorized, AuthResult::Authorized);
        assert_eq!(AuthResult::NotAuthorized, AuthResult::NotAuthorized);
        assert_eq!(AuthResult::Challenge, AuthResult::Challenge);
        assert_ne!(AuthResult::Authorized, AuthResult::NotAuthorized);
        assert_ne!(AuthResult::Authorized, AuthResult::Challenge);
    }

    #[test]
    fn test_auth_result_copy() {
        let result = AuthResult::Authorized;
        let copied = result; // Copy trait
        assert_eq!(result, copied);
    }

    #[test]
    fn test_auth_result_debug() {
        assert!(format!("{:?}", AuthResult::Authorized).contains("Authorized"));
        assert!(format!("{:?}", AuthResult::NotAuthorized).contains("NotAuthorized"));
        assert!(format!("{:?}", AuthResult::Challenge).contains("Challenge"));
    }

    // ==================== Actions Constants Tests ====================

    #[test]
    fn test_action_constants() {
        assert_eq!(actions::MANAGE, "org.ebpf-assist.manage");
        assert_eq!(actions::LOAD, "org.ebpf-assist.load");
        assert_eq!(actions::ATTACH, "org.ebpf-assist.attach");
    }

    // ==================== AuthManager Tests ====================

    #[test]
    fn test_auth_manager_default() {
        let auth = AuthManager::default();
        assert!(auth.enabled);
        assert!(auth.connection.is_none());
        assert_eq!(auth.cache_duration, DEFAULT_CACHE_DURATION);
    }

    #[test]
    fn test_auth_manager_new() {
        let auth = AuthManager::new();
        assert!(auth.enabled);
        assert!(auth.connection.is_none());
    }

    #[test]
    fn test_auth_manager_disabled() {
        let auth = AuthManager::disabled();
        assert!(!auth.enabled);
    }

    #[test]
    fn test_auth_manager_with_cache_duration() {
        let custom_duration = Duration::from_secs(60);
        let auth = AuthManager::new().with_cache_duration(custom_duration);
        assert_eq!(auth.cache_duration, custom_duration);
    }

    #[tokio::test]
    async fn test_disabled_auth() {
        let mut auth = AuthManager::disabled();
        let result = auth.check_authorization(1000, actions::LOAD).await.unwrap();
        assert_eq!(result, AuthResult::Authorized);
    }

    #[tokio::test]
    async fn test_disabled_auth_all_actions() {
        let mut auth = AuthManager::disabled();

        let result = auth
            .check_authorization(1000, actions::MANAGE)
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Authorized);

        let result = auth.check_authorization(1000, actions::LOAD).await.unwrap();
        assert_eq!(result, AuthResult::Authorized);

        let result = auth
            .check_authorization(1000, actions::ATTACH)
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Authorized);
    }

    #[tokio::test]
    async fn test_disabled_request_authorization() {
        let mut auth = AuthManager::disabled();
        let result = auth
            .request_authorization(1000, actions::LOAD)
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Authorized);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let auth = AuthManager::new();
        // Should not panic
        auth.clear_cache(Some(1000)).await;
        auth.clear_cache(None).await;
    }

    #[tokio::test]
    async fn test_cache_clear_specific_user() {
        let auth = AuthManager::new();
        // Clear for a specific user
        auth.clear_cache(Some(1000)).await;
        auth.clear_cache(Some(1001)).await;
    }

    #[tokio::test]
    async fn test_cache_clear_all_users() {
        let auth = AuthManager::new();
        // Clear all
        auth.clear_cache(None).await;
    }

    // ==================== DEFAULT_CACHE_DURATION Tests ====================

    #[test]
    fn test_default_cache_duration() {
        assert_eq!(DEFAULT_CACHE_DURATION, Duration::from_secs(15 * 60));
        assert_eq!(DEFAULT_CACHE_DURATION.as_secs(), 900);
    }
}
