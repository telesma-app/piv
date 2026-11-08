package protocol

import (
	"github.com/telesma-app/bertlv"
)

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

// EncodeSecureMessagingCertificateSigner encodes an uncompressed Secure
// Messaging Certificate Signer object without the outer 53 template, for
// PutData (SP 800-73-5 Part 1, Table 43). IntermediateCVC, when present, is
// appended with its exact tag and length encoding. It does not create or
// validate either certificate's signature.
func EncodeSecureMessagingCertificateSigner(signer SecureMessagingCertificateSigner) []byte {
	data := bertlv.Append(nil, 0x70, signer.CertificateDER)
	data = append(data, 0x71, 1, 0)
	data = append(data, signer.IntermediateCVC...)

	return append(data, 0xfe, 0)
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

	return SecureMessagingCertificateSigner{CertificateDER: certificate.DER, IntermediateCVC: intermediateCVC}, nil
}
