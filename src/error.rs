use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Cannot open wordlist file from: {}", filepath))]
    OpenWordlist { filepath: String },
    #[snafu(display("Cannot read file from: {}", filepath))]
    ReadFile { filepath: String },
    #[snafu(display("Json serialization error"))]
    JsonSerialization,
    #[snafu(display("Cannot use FromStr with given string, {}", path))]
    PathFromStr { path: String },
    #[snafu(display("Cannot use FromStr with given string, {}", child_number))]
    ChildNumberFromStr { child_number: String },
}
