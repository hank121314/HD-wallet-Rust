use crate::error;
use std::str::FromStr;

#[derive(Clone)]
pub struct ChildNumber {
    pub is_hardened: bool,
    pub index: u32,
}

impl FromStr for ChildNumber {
    type Err = error::Error;

    fn from_str(child: &str) -> Result<Self, Self::Err> {
        let (is_hardened, index) = match child.strip_suffix('\'') {
            None => (false, child),
            Some(pos) => (true, pos),
        };

        let index: u32 = index.parse().map_err(|_| error::Error::ChildNumberFromStr {
            child_number: child.to_string(),
        })?;

        Ok(Self { is_hardened, index })
    }
}
