# A Note on GCM Nonces

`uniformity` uses AES128-GCM with randomly-generated 96 bit nonces.
According to NIST guidelines, this is sufficient to use a given key up to
roughly 13 billion times.

I **speculate** that:
1) This limit is non-applicable to most use cases of `uniformity`.
2) This limit is entirely non-applicable due to the design of `uniformity`.

Please keep in mind that I am not a cryptographer for the following points.

There are three instances in which AES-GCM is used:

### Protecting the user-supplied plaintext
A unique data encryption key + nonce is generated for each encryption
operation,meaning this given key + nonce combo can only happen once.

### Using a password-generated key
A KDF-generated key should be generated with a unique salt each time,
again resulting in a technically-unique key for each operation.
This is up to the user, however, and we should encourage best practice
for this in the `uniformity` documentation.

### Using a (potentially long-lived) key encryption key.
The nonce limit is due to the potential of using the same key + nonce
on the same plaintext.
However, a key encryption key is exclusively used to protect the unique,
per-operation data encryption keys mentioned in the first point.
Since the chance of generating non-unique 128-bit value from a quality
CSPRNG is statistically zero, a repeated nonce would not be used
with a repeated plaintext DEK.
