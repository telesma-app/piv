package protocol

import (
	"strings"

	"github.com/telesma-app/bertlv"
)

// EncodeCHUID encodes a CHUID's known fields without the outer 53 template,
// for PutData (SP 800-73-5 Part 1, Table 10). Raw is ignored. The expiration
// date follows CHUID's calendar-date contract. A nil signature is omitted;
// a non-nil empty signature encodes an unsigned placeholder.
// Re-encoding does not preserve the original signed bytes or create a signature.
func EncodeCHUID(chuid CHUID) []byte {
	data := bertlv.Append(nil, 0x30, chuid.FASCN[:])
	data = bertlv.Append(data, 0x34, chuid.GUID[:])

	data = bertlv.Append(data, 0x35, []byte(chuid.ExpirationDate.Format("20060102")))
	if chuid.CardholderUUID != nil {
		data = bertlv.Append(data, 0x36, chuid.CardholderUUID[:])
	}

	if chuid.IssuerSignature != nil {
		data = bertlv.Append(data, 0x3e, chuid.IssuerSignature)
	}

	return append(data, 0xfe, 0)
}

// EncodeCCC encodes a CCC's known fields without the outer 53 template,
// for PutData (SP 800-73-5 Part 1, Table 9). Raw is ignored. Unspecified
// mandatory fields are encoded with zero length. The caller supplies field
// contents according to CCC's length contracts.
func EncodeCCC(ccc CCC) []byte {
	var cardIdentifier []byte
	if ccc.CardIdentifier != nil {
		cardIdentifier = ccc.CardIdentifier[:]
	}

	data := bertlv.Append(nil, 0xf0, cardIdentifier)
	if ccc.CapabilityContainerVersion == nil {
		data = append(data, 0xf1, 0)
	} else {
		data = append(data, 0xf1, 1, *ccc.CapabilityContainerVersion)
	}

	if ccc.CapabilityGrammarVersion == nil {
		data = append(data, 0xf2, 0)
	} else {
		data = append(data, 0xf2, 1, *ccc.CapabilityGrammarVersion)
	}

	data = bertlv.Append(data, 0xf3, ccc.ApplicationsCardURL)
	if ccc.PKCS15 == nil {
		data = append(data, 0xf4, 0)
	} else {
		data = append(data, 0xf4, 1, *ccc.PKCS15)
	}

	data = append(data, 0xf5, 1, ccc.DataModel)
	data = bertlv.Append(data, 0xf6, ccc.AccessControlRuleTable)

	return append(data, 0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0)
}

// EncodePrintedInformation encodes Printed Information without the outer 53
// template, for PutData (SP 800-73-5 Part 1, Table 15). The caller supplies
// ASCII text within the field lengths accepted by ParsePrintedInformation.
// The expiration date follows PrintedInfo's calendar-date contract.
func EncodePrintedInformation(info PrintedInfo) []byte {
	data := bertlv.Append(nil, 0x01, []byte(info.Name))
	data = bertlv.Append(data, 0x02, []byte(info.EmployeeAffiliation))
	data = bertlv.Append(data, 0x04, []byte(strings.ToUpper(info.ExpirationDate.Format("2006Jan02"))))
	data = bertlv.Append(data, 0x05, []byte(info.AgencyCardSerialNumber))

	data = bertlv.Append(data, 0x06, []byte(info.IssuerIdentification))
	if info.OrganizationAffiliationLine1 != nil {
		data = bertlv.Append(data, 0x07, []byte(*info.OrganizationAffiliationLine1))
	}

	if info.OrganizationAffiliationLine2 != nil {
		data = bertlv.Append(data, 0x08, []byte(*info.OrganizationAffiliationLine2))
	}

	return append(data, 0xfe, 0)
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

// EncodeOffCardKeyHistoryFile encodes the DER file described in SP 800-73-5
// Part 1, Sec. 3.3.3. Entries retain their order. The caller supplies one to
// twenty entries with distinct retired key references and complete certificate
// DER SEQUENCEs, as returned by ParseOffCardKeyHistoryFile. Certificate bytes
// are preserved without parsing or checking their signatures.
func EncodeOffCardKeyHistoryFile(certificates []OffCardCertificate) []byte {
	var data []byte

	for _, certificate := range certificates {
		entry := []byte{0x04, 1, byte(certificate.Key)}
		entry = append(entry, certificate.DER...)
		data = bertlv.Append(data, 0x30, entry)
	}

	return bertlv.Append(nil, 0x30, data)
}
