use sigstore::{
    bundle::{
        sign::SigningContext,
        verify::{policy, Verifier},
    },
    oauth::IdentityToken,
};
use tokio::task;

#[tokio::test]
async fn sign_on_github() {
    if let Err(_) = std::env::var("GITHUB_ACTIONS") {
        // Assume we are not in a GitHub Action: this is where we would skip a test if that was a thing
        return;
    };

    // Get token with audience "sigstore" from GitHub
    let token_content =
        task::spawn_blocking(move || ci_id::detect_credentials(Some("sigstore")).unwrap())
            .await
            .unwrap();

    let token = IdentityToken::try_from(token_content.as_str()).expect(&format!(
        "Token parsing failed with content '{}'",
        token_content
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
