//! Request handler - processes requests from clients.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::{debug, error, info};

use ebpf_assist_common::{ErrorCode, Request, Response};

use crate::caps::check_permitted_caps;
use crate::loader::Loader;

/// Shared state for the daemon.
pub struct State {
    pub loader: Loader,
    pub start_time: Instant,
}

impl State {
    pub fn new() -> Self {
        Self {
            loader: Loader::new(),
            start_time: Instant::now(),
        }
    }
}

/// Handle a request from a client.
pub async fn handle_request(state: Arc<Mutex<State>>, request: Request) -> Response {
    debug!("Handling request: {:?}", request);

    match request {
        Request::Load { path, program_name } => {
            let mut state = state.lock().await;
            match state.loader.load(&path, program_name.as_deref()) {
                Ok(info) => {
                    info!("Loaded program: {} ({:?})", info.name, info.program_type);
                    Response::Loaded {
                        id: info.id,
                        name: info.name,
                        program_type: info.program_type,
                    }
                }
                Err(e) => {
                    error!("Failed to load program: {}", e);
                    error_response(&e)
                }
            }
        }

        Request::Unload { id } => {
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
    }
}

/// Convert an error to a Response::Error with appropriate code.
fn error_response(e: &anyhow::Error) -> Response {
    let message = e.to_string();
    let code = if message.contains("not found") || message.contains("No such file") {
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
