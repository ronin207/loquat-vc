use num_bigint::BigUint;
use bincode;
use serde::{Serialize, Deserialize};

// Encoding utilities for Loquat cryptographic data
pub struct Encoding;

impl Encoding {
  // Encodes a BigUint into a byte array
  pub fn encode_biguint(value: &BigUint) -> Vec<u8> {
    value.to_bytes_be()
  }

  // Decodes a byte array into a BigUint
  pub fn decode_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
  }

  // Serialize a generic struct using Bincode
  pub fn serialize<T: Serialize>(data: &T) -> Vec<u8> {
    bincode::serialize(data).expect("Serialization failed")
  }

  // Deserialize a byte array back into a struct
  pub fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> T {
    bincode::deserialize(bytes).expect("Deserialization failed")
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde::{Serialize, Deserialize};

  #[derive(Serialize, Deserialize, Debug, PartialEq)]
  struct TestStruct {
    a: u32,
    b: String,
  }

  #[test]
  fn test_encode_decode_biguint() {
    let value = BigUint::from(123456789u128);
    let encoded = Encoding::encode_biguint(&value);
    let decoded = Encoding::decode_biguint(&encoded);
    assert_eq!(value, decoded);
  }

  #[test]
  fn test_serialize_deserialize() {
    let test_data = TestStruct { a: 42, b: "Hello Loquat".to_string() };
    let serialized = Encoding::serialize(&test_data);
    let deserialized: TestStruct = Encoding::deserialize(&serialized);
    assert_eq!(test_data, deserialized);
  }
}
