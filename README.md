# A CCA2-secure Key-Encapsulation Mechanism
## CSc 480 - Computer Security

**Team Name**: Zero Knowledge People  
**Team Members**:
* [David Hadaller](https://github.com/dahadaller)
* [Zhuobang Liu](https://github.com/bonliu)
* [Alexander Matson](https://github.com/alexmat2on)
* [Neal Rea](https://github.com/nealrea)

### Project Details
By combining a symmetric-key encryption (SKE) scheme with a public-key (RSA) scheme, we can efficiently encrypt large messages and still be able to communicate them over a public channel.

With the use of MACs, the system can be CCA2 secure as any decryption oracle will return `-1` if the input ciphertext is invalid with respect to the attached MAC.
