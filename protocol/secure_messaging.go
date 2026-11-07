package protocol

// SecureMessagingCertificateSigner contains the Secure Messaging Certificate Signer data
// object (SP 800-73-5 Part 1, Sec. 3.3.7 and Table 43). CertificateDER contains
// the decoded X.509 certificate bytes. IntermediateCVC is nil when absent;
// otherwise it contains the exact BER-TLV encoding, including tag 7F21 and its
// original length encoding. IntermediateCVC borrows the parsed object, as does
// CertificateDER when the certificate is uncompressed.
type SecureMessagingCertificateSigner struct {
	CertificateDER  []byte
	IntermediateCVC []byte
}

// ParseSecureMessagingCertificateSigner parses the object's content without
// its outer 53 template, as returned by GetData. It supports DER and GZIP
// certificate encoding and preserves the uncompressed intermediate CVC.
// Certificate contents remain encoded and signatures are not verified.
// The caller determines whether an intermediate CVC is required.
func ParseSecureMessagingCertificateSigner(data []byte) (SecureMessagingCertificateSigner, error) {
	certificate, intermediateCVC, err := decodeCertificate(data)
	if err != nil {
		return SecureMessagingCertificateSigner{}, err
	}

	return SecureMessagingCertificateSigner{CertificateDER: certificate, IntermediateCVC: intermediateCVC}, nil
}
