use reqwest;
use serde::Deserialize;
use sigstore::{
    bundle::{
        sign::SigningContext,
        verify::{policy, Verifier},
    },
    oauth::IdentityToken,
};
use std::{collections::HashMap, env};

#[derive(Deserialize)]
struct GitHubTokenResponse {
    value: String,
}

#[tokio::test]
async fn sign_on_github() {
    if let Err(_) = env::var("GITHUB_ACTIONS") {
        // Assume we are not in GH action: would be great if skipping was possible but...
        return;
    };

    // First get an OIDC token from GitHub
    let token_token = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .expect("ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable not found: is the id-token workflow permission set?");
    let token_url = env::var("ACTIONS_ID_TOKEN_REQUEST_URL").unwrap();
    let params = HashMap::from([("audience", "sigstore")]);

    let client = reqwest::Client::new();
    let token_response = client
        .get(token_url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("bearer {}", token_token),
        )
        .query(&params)
        .send()
        .await
        .unwrap()
        .json::<GitHubTokenResponse>()
        .await
        .unwrap();

    let token = IdentityToken::try_from(token_response.value.as_str()).expect(&format!(
        "Token parsing failed with content '{}'",
        token_response.value
    ));

    // Use token to sign
    let context = SigningContext::async_production().await.unwrap();
    let signer = context.signer(token).await.unwrap();

    let signing_artifact = signer.sign("".as_bytes()).await.unwrap();
    let bundle = signing_artifact.to_bundle();

    // Verify signature (only verify issuer so this works in any project and workflow)
    let verifier = Verifier::production().await.unwrap();
    let policy = policy::OIDCIssuer("https://token.actions.githubusercontent.com".to_string());
    verifier
        .verify("".as_bytes(), bundle, &policy, true)
        .await
        .expect("Unexpectedly failed to verify signature");
}
