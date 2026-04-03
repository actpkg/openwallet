//! Minimal signal-hook stub for cross-compilation targets where
//! signal-hook-registry cannot link (e.g. Android via cargo-ndk).

pub mod consts {
    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGQUIT: i32 = 3;
    pub const SIGTERM: i32 = 15;
}

pub mod iterator {
    pub struct Signals;

    impl Signals {
        pub fn new<I>(_signals: I) -> Result<Self, std::io::Error>
        where
            I: IntoIterator<Item = i32>,
        {
            Ok(Signals)
        }

        pub fn forever(&mut self) -> impl Iterator<Item = i32> {
            std::iter::empty()
        }
    }
}
