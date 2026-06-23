use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::export;
use crate::firewall;
use crate::rules::{self, RuleEntry, RuleSet};
use crate::service::{self, Service, ServiceList};
use crate::state::{
    parse_source_line, resolve_source_entry, AppState, SourceEntry, SourceList, StatsSnapshot,
};

const INDEX_HTML: &str = include_str!("../panel/index.html");
const APP_JS: &str = include_str!("../panel/app.js");
const STYLE_CSS: &str = include_str!("../panel/style.css");

pub async fn run_panel(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.server.panel_listen.parse()?;

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_js))
        .route("/style.css", get(serve_css))
        .route("/api/status", get(api_status))
        .route("/api/sources", get(api_list_sources).post(api_add_source))
        .route("/api/sources/bulk", post(api_bulk_sources))
        .route("/api/sources/{addr}", delete(api_remove_source))
        .route("/api/sources/clear", post(api_clear_sources))
        .route("/api/rules", get(api_list_rules).post(api_add_rules))
        .route("/api/rules/{index}", delete(api_remove_rule))
        .route("/api/rules/import", post(api_import_rules))
        .route("/api/rules/clear", post(api_clear_rules))
        .route("/api/firewall/apply", post(api_apply_firewall))
        .route("/api/services", get(api_list_services))
        .route("/api/services/init", post(api_init_services))
        .route("/api/services/{id}", get(api_get_service).post(api_update_service).delete(api_delete_service))
        .route("/api/services/{id}/toggle", post(api_toggle_service))
        .route("/api/export/dns.json", get(api_export_dns))
        .route("/api/export/route.json", get(api_export_route))
        .route("/api/export/status", get(api_export_status))
        .route("/api/node/info", get(api_node_info))
        .with_state(state);

    tracing::info!("Panel listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = &state.config.auth.token;
    if token == "change-me" || token.is_empty() {
        return Ok(());
    }
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth == format!("Bearer {token}") || auth == token.as_str() {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_js() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/javascript; charset=utf-8")],
        APP_JS,
    )
        .into_response()
}

async fn serve_css() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/css; charset=utf-8")],
        STYLE_CSS,
    )
        .into_response()
}

// ── Status ──

async fn api_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let snap = state.stats.snapshot();
    let rules = state.rules.load();
    let sources = state.sources.load();
    let target = state.unlock_ip.load();
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        unlock_target: target.raw.clone(),
        unlock_ip: target.ipv4.map(|ip| ip.to_string()),
        rule_count: rules.rule_count(),
        source_count: sources.entries.len(),
        firewall_enabled: state.config.firewall.enabled,
        stats: snap,
    }))
}

// ── Sources ──

async fn api_list_sources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SourceEntry>>, StatusCode> {
    check_auth(&state, &headers)?;
    let sources = state.sources.load();
    Ok(Json(sources.entries.clone()))
}

async fn api_add_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddSourceRequest>,
) -> Result<Json<SourcesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let mut entry = match parse_source_line(&req.addr) {
        Some(mut e) => {
            e.note = req.note.unwrap_or_default();
            e
        }
        None => return Err(StatusCode::BAD_REQUEST),
    };
    resolve_source_entry(&mut entry).await;

    let guard = state.sources.load();
    let mut list = SourceList::clone(&**guard);
    drop(guard);

    if !list.entries.iter().any(|e| e.addr == entry.addr) {
        list.entries.push(entry);
        list.rebuild_set();
        let _ = list.save(&state.config.sources_path());
        state.sources.store(Arc::new(list.clone()));
    }
    Ok(Json(SourcesResponse {
        count: list.entries.len(),
        entries: list.entries,
    }))
}

async fn api_bulk_sources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BulkSourcesRequest>,
) -> Result<Json<BulkSourcesResponse>, StatusCode> {
    check_auth(&state, &headers)?;

    let guard = state.sources.load();
    let mut list = SourceList::clone(&**guard);
    drop(guard);

    let mut added = 0usize;
    let mut failed = Vec::new();

    for line in req.text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_source_line(line) {
            Some(mut entry) => {
                if list.entries.iter().any(|e| e.addr == entry.addr) {
                    continue;
                }
                resolve_source_entry(&mut entry).await;
                if entry.is_domain && entry.resolved.is_empty() {
                    failed.push(format!("{} (resolve failed)", entry.addr));
                    list.entries.push(entry);
                } else {
                    list.entries.push(entry);
                }
                added += 1;
            }
            None => {
                failed.push(line.to_string());
            }
        }
    }

    list.rebuild_set();
    let _ = list.save(&state.config.sources_path());
    state.sources.store(Arc::new(list.clone()));

    Ok(Json(BulkSourcesResponse {
        added,
        total: list.entries.len(),
        failed,
    }))
}

async fn api_remove_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(addr): Path<String>,
) -> Result<Json<SourcesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let guard = state.sources.load();
    let mut list = SourceList::clone(&**guard);
    drop(guard);
    list.entries.retain(|e| e.addr != addr);
    list.rebuild_set();
    let _ = list.save(&state.config.sources_path());
    let resp = SourcesResponse {
        count: list.entries.len(),
        entries: list.entries.clone(),
    };
    state.sources.store(Arc::new(list));
    Ok(Json(resp))
}

async fn api_clear_sources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SourcesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let list = SourceList::default();
    let _ = list.save(&state.config.sources_path());
    state.sources.store(Arc::new(list));
    Ok(Json(SourcesResponse {
        count: 0,
        entries: vec![],
    }))
}

// ── Rules ──

async fn api_list_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RulesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let rules = state.rules.load();
    Ok(Json(RulesResponse {
        total: rules.rule_count(),
        entries: rules.entries.clone(),
    }))
}

async fn api_add_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddRulesRequest>,
) -> Result<Json<RulesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let mut current = state.rules.load().entries.clone();
    current.extend(req.entries);
    let mut set = RuleSet::from_entries(current);
    set.rebuild();
    save_custom_rules(&state, &set.entries);
    let count = set.rule_count();
    let entries = set.entries.clone();
    state.rules.store(Arc::new(set));
    Ok(Json(RulesResponse {
        total: count,
        entries,
    }))
}

async fn api_remove_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(index): Path<usize>,
) -> Result<Json<RulesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let mut entries = state.rules.load().entries.clone();
    if index < entries.len() {
        entries.remove(index);
    }
    let mut set = RuleSet::from_entries(entries);
    set.rebuild();
    save_custom_rules(&state, &set.entries);
    let count = set.rule_count();
    let entries = set.entries.clone();
    state.rules.store(Arc::new(set));
    Ok(Json(RulesResponse {
        total: count,
        entries,
    }))
}

async fn api_import_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let new_entries = rules::load_rules_from_text(&req.text);
    let added = new_entries.len();
    let mut current = state.rules.load().entries.clone();
    current.extend(new_entries);
    let mut set = RuleSet::from_entries(current);
    set.rebuild();
    save_custom_rules(&state, &set.entries);
    let total = set.rule_count();
    state.rules.store(Arc::new(set));
    Ok(Json(ImportResponse { added, total }))
}

async fn api_clear_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RulesResponse>, StatusCode> {
    check_auth(&state, &headers)?;
    let set = RuleSet::default();
    save_custom_rules(&state, &set.entries);
    state.rules.store(Arc::new(set));
    Ok(Json(RulesResponse {
        total: 0,
        entries: vec![],
    }))
}

async fn api_apply_firewall(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let backend = firewall::detect_backend(&state.config.firewall.backend);
    let mut ports = vec![53u16, 443];
    if !state.config.server.http_listen.is_empty() {
        ports.push(80);
    }
    firewall::apply_rules(&state, backend, &ports);
    Ok(Json(
        serde_json::json!({"ok": true, "backend": format!("{backend:?}")}),
    ))
}

fn save_custom_rules(state: &AppState, entries: &[RuleEntry]) {
    let path = state.config.custom_rules_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(entries).unwrap_or_default(),
    );
}

fn save_services(state: &AppState, list: &ServiceList) {
    let _ = list.save(&state.config.services_path());
}

fn regenerate_export(state: &Arc<AppState>) {
    let result = export::generate(state);
    let dir = state.config.export_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("dns.json"), &result.dns_json);
    let _ = std::fs::write(dir.join("route.json"), &result.route_json);
}

// ── Services ──

async fn api_list_services(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Service>>, StatusCode> {
    check_auth(&state, &headers)?;
    let list = state.services.load();
    Ok(Json(list.services.clone()))
}

async fn api_get_service(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Service>, StatusCode> {
    check_auth(&state, &headers)?;
    let list = state.services.load();
    list.find(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn api_init_services(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let guard = state.services.load();
    let mut list = ServiceList::clone(&**guard);
    drop(guard);

    let builtins = service::builtin_services();
    let mut added = 0usize;
    for svc in builtins {
        if !list.services.iter().any(|s| s.id == svc.id) {
            list.services.push(svc);
            added += 1;
        }
    }
    save_services(&state, &list);
    state.services.store(Arc::new(list));
    Ok(Json(serde_json::json!({"added": added})))
}

async fn api_update_service(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(svc): Json<Service>,
) -> Result<Json<Service>, StatusCode> {
    check_auth(&state, &headers)?;
    let guard = state.services.load();
    let mut list = ServiceList::clone(&**guard);
    drop(guard);

    if let Some(existing) = list.find_mut(&id) {
        existing.name = svc.name;
        existing.icon = svc.icon;
        existing.enabled = svc.enabled;
        existing.domains = svc.domains;
        existing.cidrs = svc.cidrs;
        existing.geosite = svc.geosite;
        existing.geoip = svc.geoip;
    } else {
        let mut new_svc = svc;
        new_svc.id = id;
        list.services.push(new_svc);
    }

    save_services(&state, &list);
    regenerate_export(&state);
    let result = list.find(&list.services.last().map(|s| s.id.as_str()).unwrap_or("")).cloned();
    state.services.store(Arc::new(list));
    result.map(Json).ok_or(StatusCode::INTERNAL_SERVER_ERROR)
}

async fn api_toggle_service(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Service>, StatusCode> {
    check_auth(&state, &headers)?;
    let guard = state.services.load();
    let mut list = ServiceList::clone(&**guard);
    drop(guard);

    let svc = list.find_mut(&id).ok_or(StatusCode::NOT_FOUND)?;
    svc.enabled = !svc.enabled;
    let result = svc.clone();

    save_services(&state, &list);
    regenerate_export(&state);
    state.services.store(Arc::new(list));
    Ok(Json(result))
}

async fn api_delete_service(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let guard = state.services.load();
    let mut list = ServiceList::clone(&**guard);
    drop(guard);

    list.services.retain(|s| s.id != id);
    save_services(&state, &list);
    regenerate_export(&state);
    state.services.store(Arc::new(list));
    Ok(Json(serde_json::json!({"ok": true})))
}

// ── Export ──

async fn api_export_dns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    check_auth(&state, &headers)?;
    let result = export::generate(&state);
    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/json; charset=utf-8"),
            ("etag", &format!("\"{}\"", result.dns_hash)),
        ],
        result.dns_json,
    )
        .into_response())
}

async fn api_export_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    check_auth(&state, &headers)?;
    let result = export::generate(&state);
    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/json; charset=utf-8"),
            ("etag", &format!("\"{}\"", result.route_hash)),
        ],
        result.route_json,
    )
        .into_response())
}

async fn api_export_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&state, &headers)?;
    let result = export::generate(&state);
    let services = state.services.load();
    let enabled = services.services.iter().filter(|s| s.enabled).count();
    Ok(Json(serde_json::json!({
        "enabled_services": enabled,
        "total_services": services.services.len(),
        "dns_hash": result.dns_hash,
        "route_hash": result.route_hash,
    })))
}

// ── Node Info ──

async fn api_node_info(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let target = state.unlock_ip.load();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "unlock_target": target.raw,
        "unlock_ip": target.ipv4.map(|ip| ip.to_string()),
    }))
}

// ── Request / Response types ──

#[derive(Deserialize)]
struct AddSourceRequest {
    addr: String,
    note: Option<String>,
}

#[derive(Deserialize)]
struct BulkSourcesRequest {
    text: String,
}

#[derive(Serialize)]
struct BulkSourcesResponse {
    added: usize,
    total: usize,
    failed: Vec<String>,
}

#[derive(Serialize)]
struct SourcesResponse {
    count: usize,
    entries: Vec<SourceEntry>,
}

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    unlock_target: String,
    unlock_ip: Option<String>,
    rule_count: usize,
    source_count: usize,
    firewall_enabled: bool,
    stats: StatsSnapshot,
}

#[derive(Serialize)]
struct RulesResponse {
    total: usize,
    entries: Vec<RuleEntry>,
}

#[derive(Deserialize)]
struct AddRulesRequest {
    entries: Vec<RuleEntry>,
}

#[derive(Deserialize)]
struct ImportRequest {
    text: String,
}

#[derive(Serialize)]
struct ImportResponse {
    added: usize,
    total: usize,
}
