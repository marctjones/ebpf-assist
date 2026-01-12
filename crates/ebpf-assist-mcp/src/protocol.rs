//! MCP protocol types (JSON-RPC 2.0).

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

/// JSON-RPC 2.0 error.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP methods we handle.
#[derive(Debug, Clone, Copy)]
pub enum McpMethod {
    Initialize,
    ToolsList,
    ToolsCall,
    Ping,
}

impl FromStr for McpMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "initialize" => Ok(McpMethod::Initialize),
            "tools/list" => Ok(McpMethod::ToolsList),
            "tools/call" => Ok(McpMethod::ToolsCall),
            "ping" => Ok(McpMethod::Ping),
            _ => Err(()),
        }
    }
}

/// Tool definition for MCP.
#[derive(Debug, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Tool call parameters.
#[derive(Debug, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// Tool call result.
#[derive(Debug, Serialize)]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// Content in tool result.
#[derive(Debug, Serialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

impl ToolCallResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent {
                content_type: "text".to_string(),
                text: text.into(),
            }],
            is_error: None,
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent {
                content_type: "text".to_string(),
                text: text.into(),
            }],
            is_error: Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== JsonRpcRequest Tests ====================

    #[test]
    fn test_json_rpc_request_deserialization() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "initialize");
    }

    #[test]
    fn test_json_rpc_request_with_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc123","method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id.as_str().unwrap(), "abc123");
    }

    #[test]
    fn test_json_rpc_request_default_params() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        // params should default to null when missing
        assert!(req.params.is_null());
    }

    #[test]
    fn test_json_rpc_request_debug() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        let debug = format!("{:?}", req);
        assert!(debug.contains("JsonRpcRequest"));
    }

    // ==================== JsonRpcResponse Tests ====================

    #[test]
    fn test_json_rpc_response_success() {
        let resp =
            JsonRpcResponse::success(serde_json::json!(1), serde_json::json!({"status": "ok"}));
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let resp =
            JsonRpcResponse::error(serde_json::json!(1), -32600, "Invalid request".to_string());
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        let error = resp.error.unwrap();
        assert_eq!(error.code, -32600);
        assert_eq!(error.message, "Invalid request");
    }

    #[test]
    fn test_json_rpc_response_serialization() {
        let resp = JsonRpcResponse::success(serde_json::json!(42), serde_json::json!("hello"));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"result\":\"hello\""));
        // error should be omitted when None
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_json_rpc_response_error_serialization() {
        let resp =
            JsonRpcResponse::error(serde_json::json!(1), -32601, "Method not found".to_string());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":-32601"));
        assert!(json.contains("\"message\":\"Method not found\""));
        // result should be omitted when None
        assert!(!json.contains("\"result\""));
    }

    // ==================== JsonRpcError Tests ====================

    #[test]
    fn test_json_rpc_error_serialization() {
        let error = JsonRpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"code\":-32700"));
        assert!(json.contains("\"message\":\"Parse error\""));
        // data should be omitted when None
        assert!(!json.contains("data"));
    }

    #[test]
    fn test_json_rpc_error_with_data() {
        let error = JsonRpcError {
            code: -32000,
            message: "Server error".to_string(),
            data: Some(serde_json::json!({"details": "connection failed"})),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"data\""));
        assert!(json.contains("\"details\""));
    }

    // ==================== McpMethod Tests ====================

    #[test]
    fn test_mcp_method_from_str_initialize() {
        let method: McpMethod = "initialize".parse().unwrap();
        assert!(matches!(method, McpMethod::Initialize));
    }

    #[test]
    fn test_mcp_method_from_str_tools_list() {
        let method: McpMethod = "tools/list".parse().unwrap();
        assert!(matches!(method, McpMethod::ToolsList));
    }

    #[test]
    fn test_mcp_method_from_str_tools_call() {
        let method: McpMethod = "tools/call".parse().unwrap();
        assert!(matches!(method, McpMethod::ToolsCall));
    }

    #[test]
    fn test_mcp_method_from_str_ping() {
        let method: McpMethod = "ping".parse().unwrap();
        assert!(matches!(method, McpMethod::Ping));
    }

    #[test]
    fn test_mcp_method_from_str_unknown() {
        let result: Result<McpMethod, ()> = "unknown".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_mcp_method_clone_copy() {
        let method = McpMethod::Initialize;
        let cloned = method.clone();
        let copied = method;
        assert!(matches!(cloned, McpMethod::Initialize));
        assert!(matches!(copied, McpMethod::Initialize));
    }

    #[test]
    fn test_mcp_method_debug() {
        let method = McpMethod::ToolsCall;
        let debug = format!("{:?}", method);
        assert!(debug.contains("ToolsCall"));
    }

    // ==================== ToolDefinition Tests ====================

    #[test]
    fn test_tool_definition_serialization() {
        let tool = ToolDefinition {
            name: "ebpf_compile".to_string(),
            description: "Compile an eBPF program".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "source": {"type": "string"}
                },
                "required": ["source"]
            }),
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("\"name\":\"ebpf_compile\""));
        assert!(json.contains("\"description\":\"Compile an eBPF program\""));
        assert!(json.contains("\"inputSchema\""));
    }

    #[test]
    fn test_tool_definition_debug() {
        let tool = ToolDefinition {
            name: "test".to_string(),
            description: "test tool".to_string(),
            input_schema: serde_json::json!({}),
        };
        let debug = format!("{:?}", tool);
        assert!(debug.contains("ToolDefinition"));
    }

    // ==================== ToolCallParams Tests ====================

    #[test]
    fn test_tool_call_params_deserialization() {
        let json = r#"{"name":"ebpf_new","arguments":{"template":"kprobe","name":"test"}}"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "ebpf_new");
        assert_eq!(params.arguments["template"], "kprobe");
    }

    #[test]
    fn test_tool_call_params_default_arguments() {
        let json = r#"{"name":"ebpf_list"}"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "ebpf_list");
        // arguments should default to null when missing
        assert!(params.arguments.is_null());
    }

    // ==================== ToolCallResult Tests ====================

    #[test]
    fn test_tool_call_result_text() {
        let result = ToolCallResult::text("Hello, world!");
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0].content_type, "text");
        assert_eq!(result.content[0].text, "Hello, world!");
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_tool_call_result_text_from_string() {
        let result = ToolCallResult::text(String::from("test"));
        assert_eq!(result.content[0].text, "test");
    }

    #[test]
    fn test_tool_call_result_error() {
        let result = ToolCallResult::error("Something went wrong");
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0].text, "Something went wrong");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_tool_call_result_serialization() {
        let result = ToolCallResult::text("test output");
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"type\":\"text\""));
        assert!(json.contains("\"text\":\"test output\""));
        // isError should be omitted when None
        assert!(!json.contains("isError"));
    }

    #[test]
    fn test_tool_call_result_error_serialization() {
        let result = ToolCallResult::error("error message");
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"isError\":true"));
    }

    // ==================== ToolContent Tests ====================

    #[test]
    fn test_tool_content_serialization() {
        let content = ToolContent {
            content_type: "text".to_string(),
            text: "hello".to_string(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"text\""));
        assert!(json.contains("\"text\":\"hello\""));
    }

    #[test]
    fn test_tool_content_debug() {
        let content = ToolContent {
            content_type: "text".to_string(),
            text: "test".to_string(),
        };
        let debug = format!("{:?}", content);
        assert!(debug.contains("ToolContent"));
    }
}
