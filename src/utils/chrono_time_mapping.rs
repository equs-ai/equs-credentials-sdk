use chrono::{DateTime, Utc};
use time::OffsetDateTime;
use time::error::ComponentRange;

pub trait TryFromChrono<C>: Sized {
    type Error;

    fn try_from_chrono(value: C) -> Result<Self, Self::Error>;
}

pub trait TryIntoTime<T>: Sized {
    type Error;

    fn try_into_time(self) -> Result<T, Self::Error>;
}

impl<C, T> TryIntoTime<T> for C
where
    T: TryFromChrono<C>,
{
    type Error = T::Error;

    fn try_into_time(self) -> Result<T, Self::Error> {
        T::try_from_chrono(self)
    }
}

pub trait TryFromTime<T>: Sized {
    type Error;

    fn try_from_time(value: T) -> Result<Self, Self::Error>;
}

pub trait TryIntoChrono<C>: Sized {
    type Error;

    fn try_into_chrono(self) -> Result<C, Self::Error>;
}

impl<C, T> TryIntoChrono<C> for T
where
    C: TryFromTime<T>,
{
    type Error = C::Error;

    fn try_into_chrono(self) -> Result<C, Self::Error> {
        C::try_from_time(self)
    }
}

impl TryFromChrono<DateTime<Utc>> for OffsetDateTime {
    type Error = ComponentRange;

    fn try_from_chrono(value: DateTime<Utc>) -> Result<Self, Self::Error> {
        let seconds = value.timestamp();
        let nanos = value.timestamp_subsec_nanos();

        let odt = OffsetDateTime::from_unix_timestamp(seconds)?;
        odt.replace_nanosecond(nanos)
    }
}

impl TryFromTime<OffsetDateTime> for DateTime<Utc> {
    type Error = ();

    fn try_from_time(value: OffsetDateTime) -> Result<Self, Self::Error> {
        let seconds = value.unix_timestamp();
        let nanos = value.nanosecond();

        DateTime::from_timestamp(seconds, nanos).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use time::macros::datetime;

    #[rstest]
    #[case(OffsetDateTime::UNIX_EPOCH, DateTime::<Utc>::from_timestamp(0, 0).unwrap())]
    #[case(
        datetime!(2025-08-13 14:59:59 UTC),
        DateTime::<Utc>::from_timestamp(1755097199, 0).unwrap()
    )]
    #[case(
        datetime!(2025-08-13 14:59:59 +4),
        DateTime::<Utc>::from_timestamp(1755082799, 0).unwrap()
    )]
    pub fn chrono_from_time(#[case] time: OffsetDateTime, #[case] expected: DateTime<Utc>) {
        let converted: DateTime<Utc> =
            DateTime::<Utc>::try_from_time(time).expect("should convert");
        assert_eq!(expected, converted);
    }

    #[rstest]
    #[case(OffsetDateTime::UNIX_EPOCH, DateTime::<Utc>::from_timestamp(0, 0).unwrap())]
    #[case(
        datetime!(2025-08-13 14:59:59 UTC),
        DateTime::<Utc>::from_timestamp(1755097199, 0).unwrap()
    )]
    #[case(
        datetime!(2025-08-13 14:59:59 +4),
        DateTime::<Utc>::from_timestamp(1755082799, 0).unwrap()
    )]
    pub fn time_to_chrono(#[case] time: OffsetDateTime, #[case] expected: DateTime<Utc>) {
        let converted: DateTime<Utc> = time.try_into_chrono().expect("should convert");
        assert_eq!(expected, converted);
    }

    #[rstest]
    #[case(DateTime::<Utc>::from_timestamp(0, 0).unwrap(), OffsetDateTime::UNIX_EPOCH)]
    #[case(
        DateTime::<Utc>::from_timestamp(1755097199, 0).unwrap(),
        datetime!(2025-08-13 14:59:59 UTC),
    )]
    #[case(
        DateTime::<Utc>::from_timestamp(1755082799, 0).unwrap(),
        datetime!(2025-08-13 14:59:59 +4)
    )]
    pub fn time_from_chrono(#[case] chrono: DateTime<Utc>, #[case] expected: OffsetDateTime) {
        let converted: OffsetDateTime =
            OffsetDateTime::try_from_chrono(chrono).expect("should convert");
        assert_eq!(expected, converted);
    }

    #[rstest]
    #[case(DateTime::<Utc>::from_timestamp(0, 0).unwrap(), OffsetDateTime::UNIX_EPOCH)]
    #[case(
        DateTime::<Utc>::from_timestamp(1755097199, 0).unwrap(),
        datetime!(2025-08-13 14:59:59 UTC),
    )]
    #[case(
        DateTime::<Utc>::from_timestamp(1755082799, 0).unwrap(),
        datetime!(2025-08-13 14:59:59 +4)
    )]
    pub fn chrono_to_time(#[case] chrono: DateTime<Utc>, #[case] expected: OffsetDateTime) {
        let converted: OffsetDateTime = chrono.try_into_time().expect("should convert");
        assert_eq!(expected, converted);
    }
}
