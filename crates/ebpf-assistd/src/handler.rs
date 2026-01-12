//! Request handler - processes requests from clients.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use ebpf_assist_common::{ErrorCode, Request, Response};

use crate::auth::{actions, AuthManager, AuthResult};
use crate::caps::check_permitted_caps;
use crate::loader::Loader;

/// Shared state for the daemon.
pub struct State {
    pub loader: Loader,
    pub auth: AuthManager,
    pub start_time: Instant,
    /// UID of the client (set per-connection).
    pub client_uid: Option<u32>,
}

impl State {
    pub fn new() -> Self {
        Self {
            loader: Loader::new(),
            auth: AuthManager::new(),
            start_time: Instant::now(),
            client_uid: None,
        }
    }

    /// Create state with authentication disabled.
    pub fn without_auth() -> Self {
        Self {
            loader: Loader::new(),
            auth: AuthManager::disabled(),
            start_time: Instant::now(),
            client_uid: None,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a request from a client.
pub async fn handle_request(state: Arc<Mutex<State>>, request: Request) -> Response {
    debug!("Handling request: {:?}", request);

    match request {
        Request::Load { path, program_name } => {
            // Check authorization first
            if let Err(resp) = check_auth(&state, actions::LOAD).await {
                return resp;
            }

            let mut state = state.lock().await;
            match state.loader.load(&path, program_name.as_deref()) {
                Ok(result) => {
                    if let Some(ref warning) = result.warning {
                        warn!("Policy warning: {}", warning);
                    }
                    info!(
                        "Loaded program: {} ({:?})",
                        result.info.name, result.info.program_type
                    );
                    Response::Loaded {
                        id: result.info.id,
                        name: result.info.name,
                        program_type: result.info.program_type,
                        warning: result.warning,
                    }
                }
                Err(e) => {
                    error!("Failed to load program: {}", e);
                    error_response(&e)
                }
            }
        }

        Request::Unload { id } => {
            // Unload doesn't require auth (we trust the user to manage their own programs)
            let mut state = state.lock().await;
            match state.loader.unload(id) {
                Ok(()) => {
                    info!("Unloaded program: {:?}", id);
                    Response::Unloaded { id }
                }
                Err(e) => {
                    error!("Failed to unload program: {}", e);
                    error_response(&e)
                }
            }
        }

        Request::Attach { id, target } => {
            // Check authorization for attach
            if let Err(resp) = check_auth(&state, actions::ATTACH).await {
                return resp;
            }

            let mut state = state.lock().await;
            match state.loader.attach(id, &target) {
                Ok(()) => {
                    info!("Attached program {:?} to {}", id, target);
                    Response::Attached { id, target }
                }
                Err(e) => {
                    error!("Failed to attach program: {}", e);
                    error_response(&e)
                }
            }
        }

        Request::Detach { id } => {
            // Detach doesn't require auth
            let mut state = state.lock().await;
            match state.loader.detach(id) {
                Ok(()) => {
                    info!("Detached program: {:?}", id);
                    Response::Detached { id }
                }
                Err(e) => {
                    error!("Failed to detach program: {}", e);
                    error_response(&e)
                }
            }
        }

        Request::List => {
            let state = state.lock().await;
            let programs = state.loader.list();
            Response::Programs { programs }
        }

        Request::Status => {
            let state = state.lock().await;
            let capabilities = check_permitted_caps().unwrap_or_default();
            Response::Status {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: state.start_time.elapsed().as_secs(),
                programs_loaded: state.loader.count(),
                capabilities,
            }
        }

        Request::Ping => Response::Pong,

        Request::Unlock => {
            let mut state = state.lock().await;
            let uid = state.client_uid.unwrap_or_else(|| {
                warn!("No client UID available, using current user");
                unsafe { libc::getuid() }
            });

            match state.auth.request_authorization(uid, actions::MANAGE).await {
                Ok(AuthResult::Authorized) => {
                    info!("User {} authorized", uid);
                    Response::Unlocked
                }
                Ok(AuthResult::NotAuthorized) => {
                    warn!("User {} authorization denied", uid);
                    Response::Error {
                        message: "Authorization denied by polkit".to_string(),
                        code: ErrorCode::AuthDenied,
                    }
                }
                Ok(AuthResult::Challenge) => {
                    // This shouldn't happen with interactive mode
                    warn!("Unexpected challenge response for user {}", uid);
                    Response::Error {
                        message: "Authorization challenge required".to_string(),
                        code: ErrorCode::AuthRequired,
                    }
                }
                Err(e) => {
                    error!("Authorization error: {}", e);
                    Response::Error {
                        message: format!("Authorization error: {}", e),
                        code: ErrorCode::Internal,
                    }
                }
            }
        }

        Request::Lock => {
            let state = state.lock().await;
            let uid = state.client_uid;
            state.auth.clear_cache(uid).await;
            info!("Authorization cache cleared for {:?}", uid);
            Response::Locked
        }

        Request::AuthStatus => {
            let state = state.lock().await;
            let _uid = state.client_uid.unwrap_or_else(|| unsafe { libc::getuid() });

            // We can't easily check expiration without accessing cache internals
            // For now, just report if currently authorized
            // TODO: Add a method to AuthManager to get cache status
            Response::AuthStatusResult {
                authorized: false, // Conservative default
                expires_in_secs: 0,
            }
        }
    }
}

/// Check authorization for an action.
/// Returns Ok(()) if authorized, Err(Response) if not.
async fn check_auth(state: &Arc<Mutex<State>>, action: &str) -> Result<(), Response> {
    let mut state = state.lock().await;
    let uid = state.client_uid.unwrap_or_else(|| {
        warn!("No client UID available, using current user");
        unsafe { libc::getuid() }
    });

    match state.auth.check_authorization(uid, action).await {
        Ok(AuthResult::Authorized) => Ok(()),
        Ok(AuthResult::Challenge) => {
            // Need to prompt user - tell them to unlock first
            Err(Response::Error {
                message: "Authorization required. Run 'ebpf-assist unlock' first.".to_string(),
                code: ErrorCode::AuthRequired,
            })
        }
        Ok(AuthResult::NotAuthorized) => Err(Response::Error {
            message: "Not authorized for this operation".to_string(),
            code: ErrorCode::AuthDenied,
        }),
        Err(e) => {
            error!("Authorization check failed: {}", e);
            // If polkit is not available, allow the operation
            // (the capabilities check will still apply)
            warn!("Polkit check failed, allowing operation: {}", e);
            Ok(())
        }
    }
}

/// Convert an error to a Response::Error with appropriate code.
fn error_response(e: &anyhow::Error) -> Response {
    let message = e.to_string();
    let code = if message.contains("Policy violation") {
        ErrorCode::PolicyViolation
    } else if message.contains("not found") || message.contains("No such file") {
        ErrorCode::NotFound
    } else if message.contains("Permission") || message.contains("Capability") {
        ErrorCode::CapabilityError
    } else if message.contains("verifier") {
        ErrorCode::VerifierError
    } else if message.contains("already attached") {
        ErrorCode::AlreadyAttached
    } else if message.contains("not attached") {
        ErrorCode::NotAttached
    } else {
        ErrorCode::Internal
    };

    Response::Error { message, code }
}
