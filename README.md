# enhanced-maurer

This crate builds upon the `maurer` crate for zero-knowledge proofs over any language $L = {(x, X) | X = \phi(x)}$
associated with a group homomorphism
$\phi(x + y) = \phi(x) + \phi(y)$ and extends it to an _enhanced_ form, in which range claim(s) are a
part of the statement, as defined in Section 4 of the "2PC-MPC: Threshold ECDSA with Thousands of Parties" paper.

# Security

We have gone through a rigorous internal auditing process throughout development, requiring the approval of two
additional cryptographers and one additional programmer in every pull request.
That being said, this code has not been audited by a third party yet; use it at your own risk.

# Releases

This code has no official releases yet, and we reserve the right to change some of the public API until then.
