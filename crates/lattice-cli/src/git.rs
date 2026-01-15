//! Git operations for the CLI

use git2::{Cred, FetchOptions, RemoteCallbacks, Repository};
use std::path::Path;

use crate::Result;

/// Clone a git repository to a local path
pub fn clone_repo(url: &str, path: &Path, credentials_path: Option<&Path>) -> Result<Repository> {
    let mut callbacks = RemoteCallbacks::new();

    callbacks.credentials(move |_url, username_from_url, allowed_types| {
        if allowed_types.contains(git2::CredentialType::SSH_KEY) {
            if let Some(creds_path) = credentials_path {
                return Cred::ssh_key(username_from_url.unwrap_or("git"), None, creds_path, None);
            }
            return Cred::ssh_key_from_agent(username_from_url.unwrap_or("git"));
        }

        if allowed_types.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
            if let Some(creds_path) = credentials_path {
                if let Ok(token) = std::fs::read_to_string(creds_path) {
                    return Cred::userpass_plaintext(
                        username_from_url.unwrap_or("git"),
                        token.trim(),
                    );
                }
            }
        }

        Cred::default()
    });

    let mut fetch_options = FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);

    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fetch_options);

    Ok(builder.clone(url, path)?)
}

/// Checkout a specific branch
pub fn checkout_branch(path: &Path, branch: &str) -> Result<()> {
    let repo = Repository::open(path)?;

    let branch_ref = format!("refs/remotes/origin/{branch}");
    let reference = repo
        .find_reference(&branch_ref)
        .or_else(|_| repo.find_reference(&format!("refs/heads/{branch}")))?;

    let commit = reference.peel_to_commit()?;
    repo.checkout_tree(commit.as_object(), None)?;
    repo.set_head(&format!("refs/heads/{branch}"))?;

    Ok(())
}
