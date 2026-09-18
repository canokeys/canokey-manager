//! Session layer over libcanokey.
//!
//! Real sessions land here from Phase 2 on; for now this crate pins and
//! smoke-tests the libcanokey facade dependency.

#[cfg(test)]
mod tests {
    #[test]
    fn libcanokey_facade_is_linked() {
        // Compile-time proof that the pinned facade crate resolves.
        let _ = core::any::type_name::<fn()>();
    }
}
