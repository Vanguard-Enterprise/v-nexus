// Rebuild when migrations change so `sqlx::migrate!` embeds the current set.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
