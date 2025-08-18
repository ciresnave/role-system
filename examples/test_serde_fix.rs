//! Test example demonstrating the serde_json::Error Clone fix.
//! 
//! Run with: cargo run --example test_serde_fix --features persistence

#[cfg(feature = "persistence")]
use role_system::error::Error;

#[cfg(feature = "persistence")]
fn main() {
    // Create a serde_json::Error by parsing invalid JSON
    let invalid_json = "{ invalid json }";
    let json_error = serde_json::from_str::<serde_json::Value>(invalid_json).unwrap_err();
    
    // Convert to our Error type (this would fail in v1.0.0)
    let our_error: Error = json_error.into();
    
    // Clone the error (this would fail in v1.0.0 due to Clone not being implemented)
    let cloned_error = our_error.clone();
    
    println!("Original error: {}", our_error);
    println!("Cloned error: {}", cloned_error);
    println!("✅ serde_json::Error Clone compatibility fix working correctly!");
    
    // Demonstrate that both errors are equivalent
    match (&our_error, &cloned_error) {
        (Error::Serialization(msg1), Error::Serialization(msg2)) => {
            assert_eq!(msg1, msg2);
            println!("✅ Error messages are preserved during conversion and cloning");
        }
        _ => panic!("Unexpected error type"),
    }
}

#[cfg(not(feature = "persistence"))]
fn main() {
    println!("This example requires the 'persistence' feature.");
    println!("Run with: cargo run --example test_serde_fix --features persistence");
}
