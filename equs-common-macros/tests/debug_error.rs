use common_macros::DebugError;
use snafu::{IntoError, Location, Snafu};

#[derive(Snafu, DebugError)]
enum KeyError {
    #[snafu(display("Key mismatch"))]
    KeyMismatch {
        #[snafu(implicit)]
        location: Location,
    },
}

#[derive(Snafu, DebugError)]
enum DidError {
    #[snafu(display("DID error"))]
    Resolve {
        #[snafu(implicit)]
        location: Location,
        source: KeyError,
    },
}

#[derive(Snafu, DebugError)]
enum VcError {
    #[snafu(display("VC error"))]
    Issue {
        #[snafu(implicit)]
        location: Location,
        source: DidError,
    },
}

#[test]
fn topmost_error_reports_its_location() {
    let key_line = line!() + 1;
    let key: KeyError = KeyMismatchSnafu.build();

    let debug = format!("{key:?}");

    assert!(
        debug.contains(&location(key_line)),
        "expected {} in:\n{debug}",
        location(key_line)
    );
}

#[test]
fn nested_errors_report_their_own_location() {
    let key_line = line!() + 1;
    let key: KeyError = KeyMismatchSnafu.build();
    let did_line = line!() + 1;
    let did: DidError = ResolveSnafu.into_error(key);
    let vc_line = line!() + 1;
    let vc: VcError = IssueSnafu.into_error(did);

    let debug = format!("{vc:?}");

    for line in [vc_line, did_line, key_line] {
        assert!(
            debug.contains(&location(line)),
            "expected {} in:\n{debug}",
            location(line)
        );
    }
}

fn location(line: u32) -> String {
    format!("{}:{}:", file!(), line)
}
