

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use actix_web::http::{header, StatusCode};
use std::time::Duration;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisResult};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct CacheState {
    manager: Option<ConnectionManager>,
    ttl_secs: usize,
}

// Capture any path segment(s) after root into `forward`
#[get("/{forward:.*}")]
async fn index(client: web::Data<reqwest::Client>, cache: web::Data<CacheState>, forward: web::Path<String>) -> impl Responder {
    // let forward = forward.into_inner();
    let mut forward = forward.into_inner();
    if !forward.starts_with("http://") && !forward.starts_with("https://") {
        forward = format!("http://{}", forward);
    }
    let key = format!("proxy:{}", forward);
    // Try cache lookup first
    if let Some(manager) = cache.manager.clone() {
        let mut cm = manager;
        let cached_json: RedisResult<String> = cm.get(&key).await;
        if let Ok(json) = cached_json {
            if let Ok(cached) = serde_json::from_str::<CachedResponse>(&json) {
                let mut builder = HttpResponse::build(StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK));
                if let Some(ct) = cached.content_type {
                    builder.insert_header((header::CONTENT_TYPE, ct));
                }
                builder.insert_header(("X-Cache", "HIT"));
                return builder.body(cached.body);
            }
        }
        // On error or deserialize failure, fall through to fetch
    }

    match client.get(&forward).send().await {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            // Read body as bytes so it works for any MIME type
            match resp.bytes().await {
                Ok(bytes) => {
                    // Store in cache on success
                    if let Some(manager) = cache.manager.clone() {
                        let mut cm = manager;
                        let to_cache = CachedResponse {
                            status: status.as_u16(),
                            content_type: content_type.clone(),
                            body: bytes.to_vec(),
                        };
                        if let Ok(json) = serde_json::to_string(&to_cache) {
                            let _: Result<(), _> = redis::pipe()
                                .set(&key, json)
                                .expire(&key, cache.ttl_secs as i64)
                                .query_async(&mut cm)
                                .await;
                        }
                    }

                    let mut builder = HttpResponse::build(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
                    if let Some(ct) = content_type {
                        builder.insert_header((header::CONTENT_TYPE, ct));
                    }
                    builder.insert_header(("X-Cache", "MISS"));
                    builder.body(bytes)
                }
                Err(e) => {
                    // If body read exceeded timeout, map to 504; otherwise 500
                    if e.is_timeout() {
                        HttpResponse::build(StatusCode::GATEWAY_TIMEOUT)
                            .body(format!("upstream timed out while reading body for {}: {}", forward, e))
                    } else {
                        HttpResponse::InternalServerError().body(format!("failed to read upstream body: {}", e))
                    }
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                HttpResponse::build(StatusCode::GATEWAY_TIMEOUT)
                    .body(format!("upstream request timed out for {}", forward))
            } else {
                HttpResponse::BadGateway().body(format!("failed to fetch {}: {}", forward, e))
            }
        }
    }
}

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();
    // Bind address from env or default
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    // Forward timeout from env in milliseconds (default 5000 ms)
    let timeout_ms: u64 = std::env::var("FORWARD_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    // Cache TTL seconds (default 60)
    let cache_ttl_secs: usize = std::env::var("CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("failed to build reqwest client");

    // Optional Redis cache
    let redis_manager = match std::env::var("REDIS_URL") {
        Ok(url) => {
            match redis::Client::open(url) {
                Ok(client) => match client.get_connection_manager().await {
                    Ok(mgr) => Some(mgr),
                    Err(e) => {
                        eprintln!("Failed to connect to Redis, continuing without cache: {}", e);
                        None
                    }
                },
                Err(e) => {
                    eprintln!("Invalid REDIS_URL, continuing without cache: {}", e);
                    None
                }
            }
        }
        Err(_) => None,
    };

    let cache_state = CacheState { manager: redis_manager, ttl_secs: cache_ttl_secs };
    println!("xx {}", cache_state.manager.is_some());
    println!(
        "Starting Actix Web server on {} (forward timeout {} ms, cache ttl {}s, cache {} )",
        bind_addr, timeout_ms, cache_ttl_secs, if cache_state.manager.is_some() { "ENABLED" } else { "DISABLED" }
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .app_data(web::Data::new(CacheState { manager: cache_state.manager.clone(), ttl_secs: cache_state.ttl_secs }))
            .service(index)
            .service(health)
            .route("/echo", web::post().to(|body: String| async move { HttpResponse::Ok().body(body) }))
    })
    .bind(bind_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use actix_web::http::{header, StatusCode};
    use std::time::Duration as StdDuration;

    async fn start_upstream() -> String {
        use actix_web::{HttpResponse, HttpServer};
        use actix_web::web::Bytes;
        // Bind to an ephemeral port we can read back
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        let server = HttpServer::new(|| {
            App::new()
                .route("/ok", actix_web::web::get().to(|| async {
                    HttpResponse::Ok()
                        .insert_header((header::CONTENT_TYPE, "text/plain"))
                        .body("hello")
                }))
                .route("/binary", actix_web::web::get().to(|| async {
                    HttpResponse::Ok()
                        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
                        .body(Bytes::from_static(&[0u8, 1, 2, 3]))
                }))
                .route("/delay", actix_web::web::get().to(|| async {
                    actix_web::rt::time::sleep(StdDuration::from_millis(200)).await;
                    HttpResponse::Ok()
                        .insert_header((header::CONTENT_TYPE, "text/plain"))
                        .body("slow")
                }))
        })
        .listen(listener)
        .unwrap()
        .run();
        actix_web::rt::spawn(server);
        base
    }


    #[actix_web::test]
    async fn test_forward_miss_preserves_status_and_content_type() {
        let base = start_upstream().await;
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_millis(1000))
            .build()
            .expect("client");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .app_data(web::Data::new(crate::CacheState { manager: None, ttl_secs: 60 }))
                .service(crate::health)
                .service(crate::index)
        ).await;

        let url = format!("{}/ok", base);
        let req = test::TestRequest::get()
            .uri(&format!("/{}", url))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
        assert_eq!(ct, "text/plain");
        let xcache = resp.headers().get("X-Cache").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert_eq!(xcache, "MISS");
        let body = test::read_body(resp).await;
        assert_eq!(body.as_ref(), b"hello");
    }

    #[actix_web::test]
    async fn test_forward_timeout_returns_504() {
        let base = start_upstream().await;
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_millis(10))
            .build()
            .expect("client");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .app_data(web::Data::new(crate::CacheState { manager: None, ttl_secs: 60 }))
                .service(crate::health)
                .service(crate::index)
        ).await; // very short timeout

        let url = format!("{}/delay", base);
        let req = test::TestRequest::get()
            .uri(&format!("/{}", url))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = test::read_body(resp).await;
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("timed out"));
    }

    #[actix_web::test]
    async fn test_health_ok() {
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_millis(1000))
            .build()
            .expect("client");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(client))
                .app_data(web::Data::new(crate::CacheState { manager: None, ttl_secs: 60 }))
                .service(crate::health)
                .service(crate::index)
        ).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        assert_eq!(body.as_ref(), b"OK");
    }
}