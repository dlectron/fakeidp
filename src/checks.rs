use actix_web::{Error, HttpResponse};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    /*
     {
      "status": "OK",
      "totalMemory" : "",
      "usedMemory" : ""
    }
     */
    pub status: &'static str,
    pub total_memory: Option<String>,
    pub used_memory: Option<String>,
}

pub async fn check() -> Result<HttpResponse, Error> {
    // sysinfo 0.40 made `System::new` fallible; the service is still healthy
    // when the memory figures cannot be read, so they are simply left out.
    let memory = sysinfo::System::new().ok().map(|mut system| {
        system.refresh_memory();
        (system.total_memory(), system.used_memory())
    });

    let response = HealthResponse {
        status: "OK",
        total_memory: memory.map(|(total, _)| total.to_string()),
        used_memory: memory.map(|(_, used)| used.to_string()),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::dev::Service;
    use actix_web::{http, test, web, App};
    // use bytes::Bytes;
    use serde_json::json;
    use serde_json::Value;
    use std::str;

    #[actix_rt::test]
    async fn test_route_check() -> Result<(), Error> {
        let app = test::init_service(
            App::new().service(web::resource("/health").route(web::get().to(check))),
        )
        .await;

        let count1_request = test::TestRequest::get()
            .uri("/health")
            .insert_header(("Content-Type", "application/json"))
            .to_request();

        let resp = app.call(count1_request).await.unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response_body = test::read_body(resp).await;
        let body_str = str::from_utf8(&response_body)
            .unwrap_or("Error with parsing result from bytes to string");
        let p: Value = serde_json::from_str(body_str).unwrap();

        println!("Value : {:?}", p);

        assert_eq!(p["status"], json!("OK"));

        Ok(())
    }
}
