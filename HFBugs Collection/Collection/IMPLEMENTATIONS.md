#### INCORRECT IMPLEMENTATION OF CRYPTO ALGOS

These bugs arise from errors in implementing cryptographic algorithms, such as incorrect mathematical operations or improper handling of cryptographic primitives.

## openssl#6687: Ed25519

- **Specification:**This bug affects the handling of Ed25519 keys in OpenSSL, specifically in version 3.0.0-alpha2. The issue manifests in cryptographic operations such as signing with functions like X509_sign, X509_CRL_sign, and X509_REQ_sign. Additionally, the extraction of public keys using EVP_PKEY_id does not return the expected identifier for Ed25519 keys, leading to failures in recognizing and processing these keys correctly.
- **Defect:**The core defect lies in the improper handling of Ed25519 public keys within OpenSSL. The functions involved fail to correctly process these keys, which results in operations returning incorrect values or failing altogether. Specifically, the EVP_PKEY_id function sometimes returns 0 instead of the correct NID_ED25519 identifier, indicating a failure to properly recognize the key type. Base 2^64 addition/subtraction and final reduction failed to treat
  partially reduced values correctly.
- **Impact:**This bug impacts cryptographic operations that rely on Ed25519 keys, particularly in the context of signing certificates or requests. It can prevent the correct signing of X.509 certificates, CRLs (Certificate Revocation Lists), and CSRs (Certificate Signing Requests), which may lead to failures in secure communications or certificate management. The failure to properly identify and process Ed25519 keys could compromise the integrity of cryptographic operations, potentially affecting the security of systems that rely on these functions.
- **Code Snippet:**

```assembly
    @@ -698,12 +698,16 @@
	add	%rax,$acc0
	adc	\$0,$acc1
-	mov	$acc0,8*0(%rdi)
	adc	\$0,$acc2
	mov	$acc1,8*1(%rdi)
	adc	\$0,$acc3
	mov	$acc2,8*2(%rdi)
+	sbb	%rax,%rax		# cf -> mask
	mov	$acc3,8*3(%rdi)
+	and	\$38,%rax
+	add	%rax,$acc0
+	mov	$acc0,8*0(%rdi)
	ret
.size	x25519_fe64_add,.-x25519_fe64_add
@@ -727,12 +731,16 @@
	sub	%rax,$acc0
	sbb	\$0,$acc1
-	mov	$acc0,8*0(%rdi)
	sbb	\$0,$acc2
	mov	$acc1,8*1(%rdi)
	sbb	\$0,$acc3
	mov	$acc2,8*2(%rdi)
+	sbb	%rax,%rax		# cf -> mask
	mov	$acc3,8*3(%rdi)
+	and	\$38,%rax
+	sub	%rax,$acc0
+	mov	$acc0,8*0(%rdi)
	ret
.size	x25519_fe64_sub,.-x25519_fe64_sub
@@ -751,6 +759,7 @@
	sar	\$63,$acc3		# most significant bit -> mask
	shr	\$1,%rax		# most significant bit cleared
	and	\$19,$acc3
+	add	\$19,$acc3		# compare to modulus in the same go
	add	$acc3,$acc0
	adc	\$0,$acc1
@@ -760,14 +769,18 @@
	lea	(%rax,%rax),$acc3
	sar	\$63,%rax		# most significant bit -> mask
	shr	\$1,$acc3		# most significant bit cleared
+	not	%rax
	and	\$19,%rax
-	add	%rax,$acc0
+	sub	%rax,$acc0
+	sbb	\$0,$acc1
+	sbb	\$0,$acc2
+	sbb	\$0,$acc3
	mov	$acc0,8*0(%rdi)
+	mov	$acc1,8*1(%rdi)
	mov	$acc2,8*2(%rdi)
	mov	$acc3,8*3(%rdi)
-	mov	$acc0,8*0(%rdi)
	ret
.size	x25519_fe64_tobytes,.-x25519_fe64_tobytes
```

## openssl#a970db05: Poly1305 Lazy Reduction in x86 ASM

- **Specification:**This issue pertains to the implementation of the Poly1305 message authentication code (MAC) in OpenSSL, specifically within the x86 assembly code. Poly1305 is used to ensure data integrity and authenticity, and the algorithm requires accurate reduction of intermediate values during its computation.
- **Defect:**The defect involves an improper or "lazy" reduction of the accumulated sum during the Poly1305 algorithm's execution in the AVX2-optimized assembly code. This lazy reduction can lead to incorrect computation of the MAC tag, which is crucial for the integrity of the message. If the reduction is not fully performed, the final MAC may be incorrect, potentially allowing attackers to tamper with the message without detection.
- **Impact:**The issue can cause the Poly1305 MAC to produce incorrect tags, compromising the integrity and authenticity guarantees provided by the algorithm. If the MAC does not correctly reflect the message's contents, attackers could exploit this to modify messages without detection, undermining the security of any system relying on this function.
- **Code Snippet:**
  The following code snippet shows the problematic and fixed sections of the x86 assembly code for Poly1305:

  ```assembly
  sub lazy_reduction {
    my $extra = shift;
  + my $paddx = defined($extra) ? paddq : paddd;

    ################################################################ lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
  @@ -563,12 +564,12 @@ sub lazy_reduction {
                            # possible, because
                            # paddq is "broken"
                            # on Atom
    - &pand      ($D1,$MASK);
    - &paddq     ($T1,$D2);           # h1 -> h2
       &psllq     ($T0,2);
    + &paddq     ($T1,$D2);           # h1 -> h2
    +  &$paddx   ($T0,$D0);           # h4 -> h0
    + &pand      ($D1,$MASK);
      &movdqa    ($D2,$T1);
      &psrlq     ($T1,26);
    -  &paddd    ($T0,$D0);           # h4 -> h0
      &pand      ($D2,$MASK);
      &paddd     ($T1,$D3);           # h2 -> h3
       &movdqa   ($D0,$T0);
  @@ -1708,18 +1709,18 @@ sub vlazy_reduction {
      &vpsrlq     ($T1,$D1,26);
      &vpand      ($D1,$D1,$MASK);
      &vpaddq     ($D2,$D2,$T1);           # h1 -> h2
    -  &vpaddd   ($D0,$D0,$T0);
    +  &vpaddq   ($D0,$D0,$T0);
       &vpsllq    ($T0,$T0,2);
      &vpsrlq     ($T1,$D2,26);
      &vpand      ($D2,$D2,$MASK);
    -  &vpaddd   ($D0,$D0,$T0);           # h4 -> h0
    - &vpaddd    ($D3,$D3,$T1);           # h2 -> h3
    +  &vpaddq   ($D0,$D0,$T0);           # h4 -> h0
    + &vpaddq    ($D3,$D3,$T1);           # h2 -> h3
      &vpsrlq     ($T1,$D3,26);
       &vpsrlq    ($T0,$D0,26);
       &vpand     ($D0,$D0,$MASK);
      &vpand      ($D3,$D3,$MASK);
    -  &vpaddd   ($D1,$D1,$T0);           # h0 -> h1
    - &vpaddd    ($D4,$D4,$T1);           # h3 -> h4
    +  &vpaddq   ($D1,$D1,$T0);           # h0 -> h1
    + &vpaddq    ($D4,$D4,$T1);           # h3 -> h4
  }
    &vlazy_reduction();
  ```

## bouncycastle#620110a#1: Bitwise Operation Bug in Bouncy Castle

- **Specification:**This issue pertains to the Bouncy Castle Java library, where a bug was discovered in the handling of bitwise operations within cryptographic code. The problem specifically affects how certain bits were masked and shifted, which is critical for ensuring accurate and secure data processing in various cryptographic algorithms. The final reduction of values was only possible after a subtraction-carry operation, which was not handled correctly in the initial implementation.
- **Defect:**The defect arises from improper bitwise operations, particularly the incorrect masking and shifting of bits. Additionally, the failure to correctly perform a subtraction-carry operation before the final reduction led to inaccurate outcomes during cryptographic processes. This mishandling compromised the reliability and correctness of the cryptographic algorithms involved.
- **Impact:**Errors in bitwise operations, combined with the incorrect handling of the subtraction-carry operation, can result in deviations from expected cryptographic results. This may affect the security and integrity of cryptographic protocols implemented in the library. Although exploiting this bug might require specific conditions, it poses a risk to systems using the affected versions of the Bouncy Castle library. Potential impacts include incorrect encryption, decryption, or hashing results, which could undermine data confidentiality, integrity, or authenticity.
- **Code Snippet:**
  The commit involves modifications to how bits are masked and shifted, as well as ensuring that the final reduction is only performed after the subtraction-carry operation. This correction is crucial to maintaining the accuracy of bitwise operations within the cryptographic functions. You can view the specific changes made in the [GitHub commit](https://github.com/bcgit/bc-java/commit/620110a9930400fcba5d00ccdc8074df488e6fa3).

## openssl#7693: Ed25519 Signature Malleability

- **Specification:**This issue pertains to the Ed25519 digital signature verification process in OpenSSL version 1.1.1. The problem arises from a lack of strict enforcement of signature validity criteria as specified in RFC 8032, section 5.1.7. Specifically, OpenSSL's implementation allows for signature malleability by not enforcing that the `s` value in the signature is less than the group order, which is a crucial requirement to prevent malleable signatures.
- **Defect:**The defect lies in the Ed25519 verification routine, where the lack of a check for the `s` value being less than the group order allows signatures that are technically invalid (according to the Ed25519 specification) to be accepted as valid. This oversight introduces the potential for signature malleability, which could undermine the security guarantees provided by the Ed25519 signature scheme.
- **Impact:**The impact of this bug is significant in scenarios where strict signature validation is required. Applications that depend on the non-malleability of Ed25519 signatures for security may be vulnerable to attacks where an attacker can create different but valid signatures for the same message. This can undermine the integrity of systems using such signatures for authentication, digital signing, or other security-critical functions.
- **Code Snippet:**The issue was resolved by updating the Ed25519 signature verification process in OpenSSL to include a check ensuring that the `s` value is less than the group order, as required by RFC 8032. This fix ensures that all signatures are correctly validated according to the Ed25519 specification, preventing the acceptance of potentially malleable signatures.
  - [OpenSSL GitHub Issue #7693](https://github.com/openssl/openssl/issues/7693)
  - [Ed25519 Signature Scheme - RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)

## CVE-2011-1945: timing openssl ecdsa

- **Specification**:
  This vulnerability exists within the Elliptic Curve Cryptography (ECC) subsystem of OpenSSL versions 1.0.0d and earlier. It specifically affects the implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA) when used with the ECDHE_ECDSA cipher suite.
  The vulnerability is tied to the incorrect implementation of curves over binary fields within the OpenSSL library. This flaw makes the system vulnerable to timing attacks. Attackers can exploit this by carefully measuring the time taken to execute cryptographic operations, which in turn can reveal information about the private keys used in these operations.
- **Defect**:
  The primary defect is the failure to correctly implement elliptic curves over binary fields in the OpenSSL ECC subsystem. This improper implementation leaves the cryptographic process vulnerable to timing attacks, which could allow attackers to recover private keys.
- **Impact**:
  The vulnerability allows context-dependent attackers to determine private keys via a combination of timing attacks and lattice calculations. This can result in the compromise of encrypted communications that rely on the affected OpenSSL versions. Given that the flaw exists at the cryptographic level, it poses a significant security risk, especially in scenarios where high confidentiality and security are required, such as in financial systems or secure communications.
- **Code Snippet**:
- [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1945)
- [Acunetix Vulnerability Details](https://www.acunetix.com/vulnerabilities/web/openssl-cryptographic-issues-vulnerability-cve-2011-1945/).

## CVE-2019-14318: Timing Side-Channel Vulnerability in Crypto++ ECDSA Implementation

- **Specification:**CVE-2019-14318 identifies a critical vulnerability in the Crypto++ library up to version 8.3.0. This issue affects the Elliptic Curve Digital Signature Algorithm (ECDSA) implementation within the library. The vulnerability is tied to a timing side-channel attack that can be exploited during the ECDSA signature generation process, potentially allowing attackers to recover private keys.
- **Defect:**The core defect lies in the non-constant time implementation of scalar multiplication during ECDSA operations. Specifically, the scalar multiplication process in the files `ecp.cpp` and `algebra.cpp` is executed in a manner that leaks information about the bit length of the scalar values. This timing variability provides an attack vector through which an adversary can infer sensitive data, such as the private key used in the cryptographic process.
- **Impact:**The vulnerability poses a significant security risk, as it allows attackers to conduct timing analysis to recover private keys over multiple ECDSA signing operations. By carefully measuring the time taken to perform scalar multiplications during these operations, attackers can deduce the bit length of the nonce (the scalar value), which is critical for constructing the private key. The ability to recover the private key compromises the cryptographic integrity of systems relying on ECDSA for secure communications and data protection.
- **Code Snippet:**The Crypto++ maintainers addressed this vulnerability by modifying the elliptic curve operations to ensure constant-time execution, thereby eliminating the timing leaks that could be exploited in side-channel attacks. The changes included the adoption of complete addition formulas in the elliptic curve operations, which are crucial for maintaining consistent execution times across different scalar values.
  - [GitHub Issue #869 on Crypto++

    ](https://github.com/weidai11/cryptopp/issues/869)

## tweetnacl-m[15]: GF(2^255-19) Freeze Bounds

- **Specification:**This issue pertains to the implementation of the finite field GF(2^255-19) within the TweetNaCl library. The problem specifically occurs in the `pack25519()` function, which is responsible for reducing numbers to ensure they remain within the correct bounds of the finite field. This function is crucial for the correct operation of cryptographic algorithms such as Curve25519 and Ed25519.
- **Defect:**The defect lies in the incorrect handling of the bounds check during the reduction process in the `pack25519()` function. Specifically, the function may fail to correctly reduce certain values, particularly when the last limb `n[15]` of the input argument exceeds or equals `0xffff`. This failure results in the scalar multiplication output not being properly reduced, leading to an incorrect packed value.
- **Impact:**This bug can lead to significant cryptographic errors, including the generation of invalid signatures or incorrect key agreement values. Such errors compromise the security and integrity of cryptographic operations, potentially rendering them vulnerable to attack. The issue is particularly critical in scenarios where precise and accurate cryptographic computations are essential.
- **Code Snippet:**
  **Buggy Version:**

  ```c
  void pack25519(u8 *o, const gf n) {
    int i, j, b;
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
      m[0] = t[0] - 0xffed;
      for(i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
        m[i-1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[15] &= 0xffff;  // This line has the bug
      sel25519(t, m, 1-b);
    }
    FOR(i, 16) {
      o[2*i] = t[i] & 0xff;
      o[2*i+1] = t[i] >> 8;
    }
  }
  ```

  **Fixed Version:**

  ```c
  void pack25519(u8 *o, const gf n) {
    int i, j, b;
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
      m[0] = t[0] - 0xffed;
      for(i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
        m[i-1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;  // Corrected line
      sel25519(t, m, 1-b);
    }
    FOR(i, 16) {
      o[2*i] = t[i] & 0xff;
      o[2*i+1] = t[i] >> 8;
    }
  }
  ```

## openssl#c2633b8f: a + b mod p256

- **Specification:**This bug relates to the modular addition operation on the P-256 elliptic curve in OpenSSL. The operation is performed using the Montgomery form on the AMD64 architecture, specifically handling addition followed by modular reduction. The addition was intended to preserve the property of the inputs being fully reduced.
- **Defect:**The defect involves the incorrect handling of the addition and subsequent modular reduction, where the addition operation failed to preserve the inputs' property of being fully reduced. This mishandling could result in incorrect field element results, leading to potential errors in elliptic curve operations.
- **Impact:**Errors in the addition and reduction process can lead to invalid outputs for elliptic curve operations, affecting critical cryptographic processes such as point addition or scalar multiplication. These inaccuracies may compromise the integrity of key exchanges or digital signatures, leading to vulnerabilities in systems that rely on P-256 elliptic curve operations. The bug reduces the robustness of cryptographic operations, potentially leading to exploitable weaknesses.
- **Code Snippet:**
  [GitHub Link to Commit

  ](https://github.com/openssl/openssl/commit/b62b2454fadfccaf5e055a1810d72174c2633b8f)

---

## **bitcoin-core/secp256k1#5de4c5d: gej_add_ge - Fix Degenerate Case in Point Addition**

* **Specification**

The function `gej_add_ge` in the secp256k1 library is responsible for computing the sum of a Jacobian point `P = (x1, y1, z1)` and an affine point `Q = (x2, y2)`. However, a degenerate case occurs when `x1 != x2` but `y1 = -y2`, leading to an undefined division-by-zero scenario during computation.

This function is crucial in Bitcoin Core’s cryptographic operations, including:

* **Transaction signing (ECDSA signatures)**
* **Public key derivation**
* **Elliptic curve operations in Taproot and Schnorr signatures**

The bug affects the correctness of these fundamental cryptographic operations.

* **Defect**

The defect arises when computing an intermediate variable `lambda`, which represents the slope of the line connecting two elliptic curve points. The standard formula is:

$$
λ=y2−y1x2−x1\lambda = \frac{y_2 - y_1}{x_2 - x_1}
$$

However, in the edge case where `y1 = -y2`, this leads to:

$$
λ=0x2−x1\lambda = \frac{0}{x_2 - x_1}
$$

which is valid as long as `x1 ≠ x2`. But if `x1 = x2`, it degenerates into `0/0`, which is undefined. This leads to incorrect results or undefined behavior in cryptographic computations.

The commit **corrects this issue** by detecting the `0/0` case and replacing `lambda` with an alternative formula:

$$
λ=y1−y2x1−x2\lambda = \frac{y_1 - y_2}{x_1 - x_2}
$$

where both versions of `lambda` are mathematically equivalent, but the alternative formulation avoids division by zero. This solution is conditionally moved (`cmov`) in place to preserve  **constant-time execution** , preventing potential  **timing attacks** .

* **Impact**
* **Incorrect cryptographic calculations** : The bug could lead to incorrect point addition results in ECDSA and Schnorr signature verifications.
* **Potential security vulnerabilities** : Incorrect elliptic curve computations could be exploited in edge cases, leading to consensus issues in Bitcoin Core.
* **Consensus compatibility risks** : If different nodes compute different results due to the bug, it could result in **chain splits** or  **invalid transactions** .
* **Potential denial-of-service (DoS) risks** : Maliciously crafted inputs could exploit this undefined behavior to crash or delay transaction processing.

By fixing this issue, Bitcoin Core ensures the correctness and security of its cryptographic operations while preserving **constant-time execution** to mitigate side-channel attacks.

* **Code Snippet**

Below is the key part of the fix applied in the commit:

```c
/** If lambda = R/M = 0/0 we have a problem (except in the "trivial"
 *  case that Z = z1z2 = 0, and this is special-cased later on). */
degenerated = secp256k1_fe_normalizes_to_zero(&m) &
              secp256k1_fe_normalizes_to_zero(&rr);
```

The fix ensures that in cases where the degenerate `0/0` condition is met, an alternative expression for `lambda` is conditionally moved into place, maintaining correctness while  **preventing timing attacks** .

[link to commit

](https://github.com/bitcoin-core/secp256k1/commit/5de4c5dffd22aa4510a5c97d0ad4a9c2eed71d85)

## **monero#1: CryptoNote Infinite Coin Vulnerability**

* **Specification**

In CryptoNote-based cryptocurrencies (e.g., Monero, Bytecoin), a **key image** is used to ensure that outputs cannot be double-spent. Key images are points on the Ed25519 elliptic curve. Under normal circumstances, each spent output has a unique key image, preventing re-spending of the same output.

However, in this bug, an attacker can manipulate key images by adding special “torsion” points (small-subgroup points) to create alternative but valid-looking key images. This effectively allows multiple spends of the same output—thus inflating the coin supply in a way that is **undetectable** unless one knows to specifically look for it.

* **Defect**
* **Nature of the Defect** :

  CryptoNote implementations did not **verify** that key images lie strictly in the main (prime-order) subgroup of Ed25519. Because Ed25519’s cofactor is 8, there exist non-trivial points in smaller subgroups. Adding one of these torsion points to a legitimate key image produces an equally valid signature from the network’s perspective—unless the code explicitly checks subgroup membership.
* **Technical Explanation** :

  Multiplying any torsion point by 8 returns the identity, so a malicious user can “factor out” this addition in the signature checks. As a result, a single real coin output can be spent multiple times with different key images that look valid unless the node code checks the key image’s subgroup membership.
* **Impact**
* **Infinite Inflation** : Attackers could create coins “out of thin air” by repeatedly spending the same output with different, undetected key images.
* **Undetectable Without Knowledge** : Observers would not notice the inflation on the blockchain unless they knew about the flaw and wrote custom checks.
* **Ecosystem Risk** : Other CryptoNote-based coins (Bytecoin, DashCoin, DigitalNote, etc.) were vulnerable if they failed to patch. Monero, Aeon, Boolberry, and Forknote patched promptly.
* **Monero’s Resolution** : Monero’s devs secretly patched and pushed mandatory updates; once the majority of the network upgraded (via a hard fork), they disclosed the vulnerability publicly.
* **Code Snippet**

While the exact code snippet is not published here (it was “surreptitiously snuck into” Monero’s codebase), the **fix** is described as:

```c
/* Pseudocode for the key image membership check */
bool valid_key_image(ec_point key_img) {
    ec_point check = scalar_mul(key_img, CURVE_ORDER_L);
    return (check == IDENTITY_ELEMENT);
}

/* If the above fails, reject the transaction. */
```

* **Mitigation** : Multiply each key image by the basepoint subgroup order `l` (for Ed25519) and verify that the result is the identity element. If not, the key image is invalid, indicating torsion abuse.

[link](https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html)

## Bug Documentation: Modular Exponentiation Bug for 65 Bits Power Input

* **Specification**

The bug occurs in the multi-buffer modular exponentiation function (`mbx_exp4096_mb8`). When the exponent input has exactly 65 bits, the computed result is completely off. For any exponent with a bit size different from 65, the function operates correctly. This subtle boundary condition can lead to significant computational errors if not detected.

* **Defect**

The defect is triggered by a very specific condition where the exponent's bit size is exactly 65. Due to this boundary condition, the internal variable `exp_bits` is set to 65, which leads to an incorrect handling of the multi-buffer modular exponentiation. A temporary workaround was introduced by aligning the exponent bit size to an 8-bit boundary, which indirectly corrects the miscalculation.

* **Impact**
* **Incorrect Modular Exponentiation:** The computation of modular exponentiation returns an entirely incorrect result when the exponent is exactly 65 bits.
* **Potential Cryptographic Failures:** In cryptographic applications that depend on accurate modular exponentiation (e.g., RSA, Diffie-Hellman), such an error could lead to incorrect outcomes or vulnerabilities.
* **Limited Trigger:** Although the condition is rare, if triggered, it can compromise the correctness of cryptographic operations.
* **Code Snippet**

```cpp
std::vector<Ipp32u> v_expo(3, 1); // Exponent intended to be 65 bits
std::vector<Ipp32u> v_base(64, 1);
std::vector<Ipp32u> v_mod(128, 2); // 4066 bits
BigNumber bn_base[8];
BigNumber bn_expo[8];
BigNumber bn_mod[8];

for (int i = 0; i < 8; ++i) {
    bn_base[i] = BigNumber(&v_base[0], v_base.size());
    bn_mod[i] = BigNumber(&v_mod[0], v_mod.size());
    bn_expo[i] = BigNumber(&v_expo[0], v_expo.size());
}

std::cout << "exp input bit size = " << bn_expo[0].BitSize() << std::endl; // 65
// With bn_expo bit size 65, the result of mbx_exp4096_mb8 is incorrect.
```

*Workaround:*

```cpp
#define BITSIZE_BYTE(n) ((((n) + 7) >> 3))
int maxExpBitLen = BITSIZE_BYTE(expBitLen) * 8;  // Aligns 65 to 72 bits, avoiding the bug.

```

[link](https://github.com/intel/cryptography-primitives/issues/39)

Below is a complete description of the Falcon variable length signatures bug, along with a corresponding vector entry. This bug falls under **IMPLEMENTATIONS.md** because it represents an implementation deviation from the expected algorithmic specification.

---

## **liboqs#1591: Falcon Variable Length Signatures**

* **Specification**

The Falcon signature scheme, as implemented in liboqs, currently produces variable-length signatures for both Falcon-512 and Falcon-1024 variants. In the existing implementation, the `sign()` function computes and returns a signature along with an output length (`signature_len`) that varies from call to call. The verification function (`verify()`) uses the provided length, so tests pass even though the actual signature length does not match the fixed size anticipated by some specifications or interoperability expectations. There is ambiguity in the Falcon specification: while the reference implementation (via pqclean) supports variable-length signatures, it is generally expected—particularly in the context of NIST submissions—that signatures should be fixed length.

* **Defect**

The bug is that the Falcon implementation in liboqs returns a variable-length signature rather than a fixed-length one. The underlying function (e.g., `PQCLEAN_FALCON512_CLEAN_comp_encode()` for Falcon-512) produces an output whose length can vary (e.g., 654 bytes vs. an expected 666 bytes for Falcon-512). While this behavior conforms to the current reference implementation from pqclean, it deviates from what many users and standards anticipate for a robust, fixed-size signature scheme. This mismatch can lead to interoperability issues or subtle bugs when integrating with systems that assume a fixed-length signature output.

* **Impact**
* **Interoperability:** Systems expecting fixed-length signatures may malfunction or reject valid signatures if they rely on hard-coded length values.
* **Standardization Concerns:** The variable-length nature might conflict with future or standardized specifications for Falcon, where fixed-length signatures are expected.
* **Security & Efficiency:** While the verification function currently adapts to the variable length, unexpected signature sizes could complicate memory management, protocol design, or further cryptographic processing.
* **Code Snippet**

In the Falcon-512 implementation (via pqclean), the issue is observed in the call chain that includes:

* `PQCLEAN_FALCON512_CLEAN_crypto_sign_signature()`, which internally calls
* `PQCLEAN_FALCON512_CLEAN_comp_encode()`

The test in `tests/test_sig.c` reveals that, for example, the allocated buffer length might be 666 bytes (as defined in `sig_falcon.h`), but the actual computed `signature_len` might be 654 bytes. This discrepancy is not caught by the verification function since it accepts the returned length.

*Note: The actual patch or code change may involve modifying the signature generation process to pad the output to a fixed length and updating the API accordingly.*

[link](https://github.com/open-quantum-safe/liboqs/issues/1591)


## pqm4 Commit `17e43e5`

* **Specification:**

  The `crypto_kem/saber/m4f` implementation of the SABER family (including LightSaber and FireSaber) performs polynomial arithmetic using Montgomery representations and Number Theoretic Transform (NTT) in ARM Cortex-M4F assembly. Correctness requires that all modular operations—particularly central reductions—are performed modulo a prime `Q` with precise register management and macro expansion behavior.
* **Defect:**

  The `NTT.S` and `NTT_inv.S` files used duplicated includes of `macros_common.S`, which led to unexpected macro redefinitions and incorrect execution of modular reduction logic in some edge cases. Furthermore, the inverse NTT (`NTT_inv.S`) applied incorrect or inconsistent reductions in the final stage, using potentially shifted results outside the expected modular range. The reduction sometimes misused constants or registers, especially under register pressure.
* **Impact:**

  Very low probability of incorrect polynomial coefficient reduction during inverse NTT computation. This may result in invalid shared secrets during KEM decapsulation, breaking correctness and potentially invalidating IND-CCA2 guarantees. The issue is rare and may not manifest in standard test vectors, but is critical for cryptographic robustness and compliance with constant-time expectations.
* **Code Snippet:**

  Example of the incorrect macro inclusion:

  ```asm
  // Before (buggy)
  #include "macros_common.S"
  ...
  #include "macros_common.S"
  ```

  Fixed with:

  ```asm
  // After (fixed)
  #include "macros_common.i"
  ```

  Example of fixed register handling and reduction:

  ```diff
  -   lsr.w   r2, r2, #16
  -   bl      montgomery_reduce
  +   bl      montgomery_reduce
  ```

  Comment correction for clarity:

  ```diff
  - // now in Montgomery domain: a_i * b_i * R mod R
  + // now in Montgomery domain: a_i * b_i * R mod Q
  ```
