use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct TagsResponse {
    models: Option<Vec<ModelInfo>>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    name: Option<String>,
}

pub async fn ensure_ollama_ready(
    base_url: &str,
    model: &str,
    client: &reqwest::Client,
) -> Result<(), OllamaSetupError> {
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    let response =
        client.get(&url).send().await.map_err(|e| {
            OllamaSetupError::OllamaNotRunning(format!("cannot reach {}: {}", url, e))
        })?;

    if !response.status().is_success() {
        return Err(OllamaSetupError::OllamaNotRunning(format!(
            "{} returned {}",
            url,
            response.status()
        )));
    }

    let body = response.text().await.map_err(OllamaSetupError::Http)?;
    let tags: TagsResponse = serde_json::from_str(&body).map_err(OllamaSetupError::Parse)?;
    let models = tags.models.unwrap_or_default();

    let has_model = models.iter().any(|m| {
        m.name
            .as_deref()
            .map(|n| n == model || n.starts_with(&format!("{}:", model)))
            .unwrap_or(false)
    });

    if has_model {
        return Ok(());
    }

    let output = Command::new("ollama")
        .arg("pull")
        .arg({
            // Validate model name to prevent pulling from arbitrary registries.
            // Validate model name: disallow '/' to prevent pulling from
            // arbitrary registries (e.g. "evil.com/trojan:latest").
            static MODEL_RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
            let re = MODEL_RE.get_or_init(|| {
                regex_lite::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]*$")
                    .expect("invalid model name pattern")
            });
            if !re.is_match(model) {
                return Err(OllamaSetupError::PullFailed(format!(
                    "invalid model name '{}': must match [a-zA-Z0-9._:-]+",
                    model
                )));
            }
            model
        })
        .output()
        .await
        .map_err(|e| OllamaSetupError::PullFailed(format!("failed to run ollama pull: {}", e)))?;

    if !output.status.success() {
        return Err(OllamaSetupError::PullFailed(format!(
            "ollama pull {} exited with {:?}",
            model, output.status
        )));
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum OllamaSetupError {
    #[error("Ollama not running: {0}")]
    OllamaNotRunning(String),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("pull failed: {0}")]
    PullFailed(String),
}
