# CBC-CTR-encryption-systems by Roman Bityutskiy

This is a program that showcases two methods of block chain encryption: Cipher-block chaining & Randomized counter mode.
Both of these encryption systems use an AES-128 implementation that is built in to the program, so there is no need to
import any external modules for the code to work. Please note that while these implementations of CBC & CTR are
mathematically correct and semantically secure, they do not provide message authentication and they may be vulnerable
to various side-channel attacks. Therefore, this program should not be used in actual situations encrypting sensitive
information, and rather should be used as an example of how the inner-workings of AES and block chaining could be coded.