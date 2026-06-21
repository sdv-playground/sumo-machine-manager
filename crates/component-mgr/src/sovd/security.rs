/// Pluggable security provider for seed/key challenge-response.
///
/// Implement this trait to plug in a production HSM or proprietary
/// key derivation algorithm. The default [`TestSecurityProvider`] uses
/// a simple XOR scheme suitable for development and testing.
use nv_store::types::BankSet;

/// Security algorithm abstraction — seed generation + key validation.
pub trait SecurityProvider: Send + Sync {
    /// Generate a random seed for the given component and security level.
    fn generate_seed(&self, component: BankSet, level: u8) -> Vec<u8>;

    /// Validate a key against a previously generated seed.
    fn validate_key(&self, component: BankSet, level: u8, seed: &[u8], key: &[u8]) -> bool;
}

/// Test/development security provider.
///
/// Seed: 4 random bytes.
/// Key: each seed byte XORed with 0xFF.
///
/// SOVD Explorer users can compute the key manually or via a security
/// helper that implements this trivial algorithm.
pub struct TestSecurityProvider;

impl SecurityProvider for TestSecurityProvider {
    fn generate_seed(&self, _component: BankSet, _level: u8) -> Vec<u8> {
        let mut seed = [0u8; 4];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        seed.to_vec()
    }

    fn validate_key(&self, _component: BankSet, _level: u8, seed: &[u8], key: &[u8]) -> bool {
        if seed.len() != key.len() {
            return false;
        }
        seed.iter().zip(key).all(|(s, k)| *k == (*s ^ 0xFF))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_roundtrip() {
        let provider = TestSecurityProvider;
        let seed = provider.generate_seed(BankSet::Vm1, 1);
        assert_eq!(seed.len(), 4);

        let key: Vec<u8> = seed.iter().map(|b| b ^ 0xFF).collect();
        assert!(provider.validate_key(BankSet::Vm1, 1, &seed, &key));
    }

    #[test]
    fn test_provider_rejects_wrong_key() {
        let provider = TestSecurityProvider;
        let seed = provider.generate_seed(BankSet::Vm1, 1);
        let bad_key = vec![0x00; 4];
        // Only passes if seed happens to be all 0xFF, astronomically unlikely
        if seed != vec![0xFF; 4] {
            assert!(!provider.validate_key(BankSet::Vm1, 1, &seed, &bad_key));
        }
    }

    #[test]
    fn test_provider_rejects_wrong_length() {
        let provider = TestSecurityProvider;
        let seed = provider.generate_seed(BankSet::Vm1, 1);
        assert!(!provider.validate_key(BankSet::Vm1, 1, &seed, &[0x00; 2]));
    }
}
