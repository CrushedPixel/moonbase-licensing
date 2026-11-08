use super::*;

/// Changing the timeout doesn't affect agents that were already created.
#[test]
fn agents_keep_the_timeout_from_when_they_were_created() {
    let previous = request_timeout_secs();
    set_request_timeout_secs(7);
    let first = moonbase_agent();
    set_request_timeout_secs(19);
    let second = moonbase_agent();
    set_request_timeout_secs(previous);

    assert_eq!(
        first.config().timeouts().global,
        Some(Duration::from_secs(7))
    );
    assert_eq!(
        second.config().timeouts().global,
        Some(Duration::from_secs(19))
    );
}
