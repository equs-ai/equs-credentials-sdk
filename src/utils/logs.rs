use super::b64;
use std::fmt::{Display, Formatter};

const MAX_UNICODE_ESCAPE_LEN: usize = 9; // example: '\u{1f9ff}' is 9 bytes in ASCII

pub(crate) enum LogMessage<'a> {
    Origin(&'a str),
    Encoded(String),
}

impl Display for LogMessage<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LogMessage::Origin(s) => s,
            LogMessage::Encoded(s) => s.as_str(),
        };

        write!(f, "{}", s)
    }
}

pub(crate) fn sanitize_log_msg(message: &str) -> LogMessage {
    let encoding_not_required = message.chars().all(is_character_allowed);

    if encoding_not_required {
        LogMessage::Origin(message)
    } else {
        LogMessage::Encoded(encode_message(message))
    }
}

fn is_character_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c.is_whitespace()
}

fn encode_message(message: &str) -> String {
    let mut encoded_message = String::with_capacity(calc_encoded_message_max_size(message));

    for character in message.chars() {
        if is_character_allowed(character) {
            encoded_message.push(character);
        }
    }

    encoded_message.push('[');
    encoded_message.push_str(&b64::encode(message.as_bytes()));
    encoded_message.push(']');

    encoded_message
}

fn calc_encoded_message_max_size(message: &str) -> usize {
    // Encoded message format is:
    // <unicode-escaped-original-message>[<base64-encoded-original-message>]

    // Number of chars can vary depending on lenght of each UTF-8 char
    let max_chars_number = message.len();

    let max_escaped_msg_len = MAX_UNICODE_ESCAPE_LEN * max_chars_number;

    // Each 4 ASCII char (4 bytes) encode 3 bytes of original data.
    // +1 is for cases the number is not divisible by 3
    let b64_encoded_msg_len = message.len() * 4 / 3 + 1;

    // Brackets '[' and ']' embrace base64-encoded original message.
    // Both '[' and ']' are 2 ASCII char (2 bytes)
    let encoded_msg_brackets_len = 2;

    max_escaped_msg_len + b64_encoded_msg_len + encoded_msg_brackets_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("test")]
    #[case("test123")]
    #[case("test 123")]
    #[tokio::test]
    async fn alphanumeric_message_is_not_changed(#[case] message: &str) {
        let log_msg = sanitize_log_msg(message);

        assert!(matches!(
            log_msg,
            LogMessage::Origin(s) if s == message
        ));
    }

    #[rstest]
    #[case("test@123", r"test123[dGVzdEAxMjM]")]
    #[tokio::test]
    async fn non_alphanumeric_message_is_encoded(#[case] message: &str, #[case] encoded: &str) {
        let log_message = sanitize_log_msg(message);

        assert!(matches!(
            log_message,
            LogMessage::Encoded(s) if s == encoded
        ));
    }

    #[rstest]
    #[case("test 123")]
    #[tokio::test]
    async fn origin_log_message_is_formatted_properly(#[case] message: &str) {
        let log_msg = LogMessage::Origin(message);

        assert_eq!(format!("{log_msg}"), format!("{message}"),);
    }

    #[rstest]
    #[case(r"test123[dGVzdEAxMjM]")]
    #[tokio::test]
    async fn encoded_log_message_is_formatted_properly(#[case] encoded_message: &str) {
        let log_msg = LogMessage::Encoded(encoded_message.to_string());

        assert_eq!(format!("{log_msg}"), format!("{encoded_message}"),);
    }
}
