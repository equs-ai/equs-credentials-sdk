/// `DataSize` enum represents amount of data
/// that can be converted to number of bytes easily
#[derive(Debug)]
pub enum DataSize {
    Bytes(usize),
    KBytes(usize),
    MBytes(usize),
    GBytes(usize),
}

impl From<DataSize> for usize {
    fn from(value: DataSize) -> Self {
        match value {
            DataSize::Bytes(number) => number,
            DataSize::KBytes(number) => (1 << 10) * number,
            DataSize::MBytes(number) => (1 << 20) * number,
            DataSize::GBytes(number) => (1 << 30) * number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DataSize;
    use rstest::rstest;

    #[rstest]
    #[case::bytes(DataSize::Bytes(2), 2)]
    #[case::kbytes(DataSize::KBytes(2), 2048)]
    #[case::mbytes(DataSize::MBytes(2), 2097152)]
    #[case::gbytes(DataSize::GBytes(2), 2147483648)]
    #[tokio::test]
    async fn data_size_value_is_converted_correctly(
        #[case] data_size: DataSize,
        #[case] expected: usize,
    ) {
        let data_size_in_bytes: usize = data_size.into();
        assert_eq!(data_size_in_bytes, expected);
    }
}
