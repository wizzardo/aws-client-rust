use std::{env, fs};
use chrono::{DateTime, Local, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use ureq::{Error, Response};
use sha2::{Sha256, Digest};
use xmltree::{Element, EmitterConfig};

fn main() -> Result<(), ureq::Error> {
    let args: Vec<String> = env::args().collect();

    let mut region: Option<&str> = None;
    let mut service: Option<&str> = None;
    let mut path: Option<&str> = None;
    let mut data: Option<&str> = None;
    let mut debug: bool = false;

    for i in 0..args.len() {
        let arg = &args[i];
        if !arg.starts_with("--") {
            continue;
        }
        match arg.as_str() {
            "--region" => {
                region = Some(args.get(i + 1).expect("missing argument value for --region"))
            }
            "--service" => {
                service = Some(args.get(i + 1).expect("missing argument value for --service"))
            }
            "--path" => {
                path = Some(args.get(i + 1).expect("missing argument value for --path"))
            }
            "--data" => {
                data = Some(args.get(i + 1).expect("missing argument value for --data"))
            }
            "--debug" => {
                debug = true
            }
            "--help" => {
                println!("{} --service <service> --path <path> --data <data> --debug --region <region> ", args[0])
            }
            _ => {
                panic!("unknown argument '{}'", arg);
            }
        }
    }

    let service = service.expect("missing argument '--service'");
    // let region = region.unwrap_or(if is_global_service(service) { "aws-global" } else { "eu-central-1" });
    let region = region.unwrap_or(if is_global_service(service) { "us-east-1" } else { "eu-central-1" });
    let path = path.expect("missing argument '--path'");

    if service.eq("meta") || service.eq("meta-data") {
        let result = get_meta_data(path)?;
        println!("{}", result);
        return Ok(());
    }

    let credentials = get_credentials_from_env()
        .or_else(get_credentials_from_profile)
        .or_else(get_credentials_from_meta_data);

    // let credentials = get_credentials_from_meta_data();
    // println!("credentials: {:?}", credentials);

    if credentials.is_none() {
        println!("Cannot find any credentials");
        return Ok(());
    }
    let credentials = credentials.unwrap();
    // println!("credentials: {:?}", credentials);
    // println!("credentials.key_id: {:?}", credentials.key_id);
    // println!("credentials.secret: {:?}", credentials.secret);

    // let region = "eu-central-1";
    // let service = "s3";
    // let bucket = "hf-stage-attachments";
    // let path = format!("/{bucket}/");
    let host = if is_global_service(service) {
        format!("{service}.amazonaws.com")
    } else {
        format!("{service}.{region}.amazonaws.com")
    };

    let empty_body: [u8; 0] = [];

    let body: &[u8] = match data {
        None => { &empty_body }
        Some(data) => { data.as_bytes() }
    };

    let url = format!("https://{host}{path}");

    let now: DateTime<Local> = Local::now();
    let now_utc: DateTime<Utc> = Utc::now();

    let date_long = now.format("%a, %d %b %Y %T %Z").to_string();
    let date_short = now_utc.format("%Y%m%d").to_string();
    let date_iso = now_utc.format("%Y%m%dT%H%M%SZ").to_string();

    // println!("{}", date_long);
    // println!("{}", date_short);
    // println!("{}", date_iso);
    // println!("{}", now_utc.timestamp_millis());

    let payload_hash = get_sha256(body);

    let content_length = body.len().to_string();

    let mut request = match body.len() {
        0 => { ureq::get(url.as_str()) }
        _ => {
            ureq::post(url.as_str())
                .set("content-length", content_length.as_str())
                .set("content-type", if body[0] == b'{' { "application/json" } else { "text/xml" })
        }
    }
        .set("Date", date_long.as_str())
        .set("x-amz-content-sha256", payload_hash.as_str())
        .set("x-amz-date", date_iso.as_str())
        ;

    if let Some(token) = &credentials.token {
        request = request.set("x-amz-security-token", token.as_str())
    }

    let mut headers: Vec<(String, String)> = request.header_names().iter().map(|key| (key.to_lowercase(), request.header(key).unwrap().to_string())).collect();

    headers.push(("host".to_string(), host));
    // if body.len() != 0 {
    //     headers.push(("content-length".to_string(), body.len().to_string()));
    // }
    headers.sort_by(|(a, _), (b, _)| { a.cmp(b) });

    // println!("{:?}", headers);

    let canonical_request = build_canonical_request(request.method(), path, payload_hash.as_str(), &headers, &vec![]);
    if debug {
        println!("{}", std::str::from_utf8(canonical_request.as_slice()).unwrap());
    }

    let request_hash = get_sha256(canonical_request.as_slice());
    // println!("request_hash: {request_hash}");

    let data = format!("AWS4-HMAC-SHA256\n{date_iso}\n{date_short}/{region}/{service}/aws4_request\n{request_hash}");
    let signature_key = get_signature_key(credentials.secret.as_str(), date_short.as_str(), region, service);
    let signature = get_hmac_sha256(signature_key.as_slice(), data.as_bytes());
    // let signature = format!("{:02x}", signature.as_slice());
    let signature = signature.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    let header_names: Vec<&str> = headers.iter().map(|(key, _)| key.as_str()).collect();
    let header_names = header_names.join(";");

    let key_id = credentials.key_id;
    let result = format!("AWS4-HMAC-SHA256 Credential={key_id}/{date_short}/{region}/{service}/aws4_request,SignedHeaders={header_names},Signature={signature}");
    // println!("{}", result);

    request = request.set("Authorization", result.as_str());

    let response: Response = match request.method() {
        "POST" => { request.send_bytes(body)? }
        _ => { request.call()? }
    };

    if debug || response.status() >= 400 {
        println!("status: {}", response.status());
        for header_name in response.headers_names().iter() {
            println!("{header_name}: {}", response.header(header_name).unwrap());
        }
        println!();
    }

    if let Some(content_type) = response.header("content-type") {
        match content_type {
            "text/xml" => {
                let response_body = response.into_string()?;
                let xml = reformat_xml(response_body.as_bytes());
                println!("{}", std::str::from_utf8(xml.as_slice()).unwrap());
            }
            _ => {
                let response_body = response.into_string()?;
                println!("{}", response_body);
            }
        }
    }


    // let body: String = ureq::get(url.as_str())
    //     .call()?
    //     .into_string()?;
    //
    // println!("{}", body);

    Ok(())
}

fn get_meta_data(path: &str) -> Result<String, Error> {
    let url = format!("http://169.254.169.254/latest/meta-data{path}");
    let response = ureq::get(url.as_str()).call();

    if let Err(e) = response {
        match e {
            Error::Status(_, r) => {
                if r.status() == 401 {
                    let token = ureq::put("http://169.254.169.254/latest/api/token")
                        .set("X-aws-ec2-metadata-token-ttl-seconds", "60")
                        .call()?
                        .into_string()?;
                    let response = ureq::get(url.as_str())
                        .set("X-aws-ec2-metadata-token", token.as_str())
                        .call()?;
                    let body = response.into_string()?;
                    Ok(body)
                } else {
                    Err(Error::from(r))
                }
            }
            Error::Transport(e) => {
                Err(Error::from(e))
            }
        }
    } else {
        let body = response?.into_string()?;
        Ok(body)
    }
}

fn get_signature_key(secret: &str, date_short: &str, region: &str, service: &str) -> Vec<u8> {
    let key = format!("AWS4{secret}");
    let mut k = key.as_bytes();
    let vec = get_hmac_sha256(k, date_short.as_bytes());
    k = vec.as_slice();
    let vec = get_hmac_sha256(k, region.as_bytes());
    k = vec.as_slice();
    let vec = get_hmac_sha256(k, service.as_bytes());
    k = vec.as_slice();
    let vec = get_hmac_sha256(k, b"aws4_request");
    vec
}

fn build_canonical_request(method: &str, path: &str, payload_hash: &str, headers: &Vec<(String, String)>, params: &Vec<(String, String)>) -> Vec<u8> {
    let mut builder: Vec<u8> = Vec::with_capacity(1024);
    builder.extend_from_slice(method.as_bytes());
    builder.push(b'\n');
    builder.extend_from_slice(path.as_bytes());
    builder.push(b'\n');

    for (i, (key, value)) in params.iter().enumerate() {
        if i > 0 {
            builder.push(b'&');
        }

        builder.extend_from_slice(key.as_bytes());
        builder.push(b'=');
        builder.extend_from_slice(value.as_bytes());
    }
    builder.push(b'\n');

    for (key, value) in headers.iter() {
        builder.extend_from_slice(key.as_bytes());
        builder.push(b':');
        builder.extend_from_slice(value.as_bytes());
        builder.push(b'\n');
    }
    builder.push(b'\n');


    for (i, (key, _)) in headers.iter().enumerate() {
        if i > 0 {
            builder.push(b';');
        }

        builder.extend_from_slice(key.as_bytes());
    }
    builder.push(b'\n');

    builder.extend_from_slice(payload_hash.as_bytes());
    builder
}

fn is_global_service(service: &str) -> bool {
    match service {
        "iam" => { true }
        "route53" => { true }
        "cloudfront" => { true }
        "waf" => { true }
        "shield" => { true }
        "globalaccelerator" => { true }
        _ => { false }
    }
}

#[derive(Debug)]
struct Credentials {
    key_id: String,
    secret: String,
    region: Option<String>,
    token: Option<String>,
}

fn get_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn get_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hasher.update(data);
    let result = hasher.finalize();
    let code_bytes = result.into_bytes();
    code_bytes.to_vec()
}


fn get_credentials_from_env() -> Option<Credentials> {
    let secret = env::var("AWS_SECRET_ACCESS_KEY");
    let key_id = env::var("AWS_ACCESS_KEY_ID");
    let region = env::var("AWS_REGION");
    let region = if let Ok(region) = region { Some(region) } else { None };

    if let Ok(secret) = secret {
        if let Ok(key_id) = key_id {
            return Some(Credentials {
                key_id,
                secret,
                region,
                token: None,
            });
        }
    }

    None
}

#[allow(nonstandard_style)]
#[derive(Deserialize)]
struct SecurityCredentials {
    AccessKeyId: String,
    SecretAccessKey: String,
    Token: String,
}

fn get_credentials_from_meta_data() -> Option<Credentials> {
    return match get_meta_data("/iam/security-credentials") {
        Ok(role) => {
            let role = role.split_once('\n').map(|(it, _)| it).unwrap_or_else(|| role.as_str());
            let path = format!("/iam/security-credentials/{role}");
            match get_meta_data(path.as_str()) {
                Ok(json) => {
                    println!("json: {json}");
                    let data: SecurityCredentials = serde_json::from_str(json.as_str()).unwrap();
                    let region = Some(get_meta_data("/placement/region").unwrap());
                    Some(Credentials {
                        key_id: data.AccessKeyId,
                        secret: data.SecretAccessKey,
                        token: Some(data.Token),
                        region,
                    })
                }
                Err(_) => { None }
            }
        }
        Err(_) => { None }
    };
}

fn get_credentials_from_profile() -> Option<Credentials> {
    let home = env::var("HOME").unwrap();
    // println!("{:?}", home);

    return match fs::read_to_string(format!("{}/.aws/credentials", home)) {
        Ok(s) => {
            let mut is_selected_profile = false;
            let mut key_id: Option<String> = None;
            let mut secret: Option<String> = None;
            let mut region: Option<String> = None;

            for line in s.lines() {
                if line.is_empty() {
                    continue;
                }

                if line.starts_with('[') {
                    is_selected_profile = line.eq("[default]");
                } else if is_selected_profile {
                    let (key, value) = line.split_once('=').unwrap();
                    match key.trim() {
                        "aws_access_key_id" => { key_id = Some(value.trim().to_string()) }
                        "aws_secret_access_key" => { secret = Some(value.trim().to_string()) }
                        "region" => { region = Some(value.trim().to_string()) }
                        _ => {}
                    }
                }
            }
            if key_id.is_some() && secret.is_some() {
                Some(Credentials {
                    key_id: key_id.unwrap(),
                    secret: secret.unwrap(),
                    region,
                    token: None,
                })
            } else {
                None
            }
        }
        Err(_) => { None }
    };
}

fn reformat_xml(data: &[u8]) -> Vec<u8> {
    let el = Element::parse(data).expect("parsexml");
    let mut cfg = EmitterConfig::new();
    cfg.perform_indent = true;
    let mut writer = Vec::with_capacity(data.len() + 1024);
    el.write_with_config(&mut writer, cfg).expect("writexml");
    writer
}