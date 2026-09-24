pub type Result<T> = std::result::Result<T, String>;
pub fn err<S: Into<String>>(s: S) -> String {
    s.into()
}
