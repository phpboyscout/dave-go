package mediakeys

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// ExportWithMLSExporterSecret derives application secret material directly from
// an MLS exporter secret using the label/context construction expected by
// Discord's DAVE reference implementations.
func ExportWithMLSExporterSecret(
	exporterSecret *ciphersuite.Secret,
	cs ciphersuite.CipherSuite,
	label string,
	context []byte,
	length int,
) ([]byte, error) {
	if exporterSecret == nil {
		return nil, ErrNilExporterSecret
	}

	derivedSecret, err := exporterSecret.DeriveSecret(cs, label)
	if err != nil {
		return nil, fmt.Errorf("derive exporter label %q: %w", label, err)
	}

	contextHash, err := ciphersuite.Hash(cs, context)
	if err != nil {
		return nil, fmt.Errorf("hash exporter context: %w", err)
	}

	// RFC 9420 §8.5 expands with "exported" here, not "exporter", as mlspp
	// and libdave do.
	exportedSecret, err := derivedSecret.KdfExpandLabel("exported", contextHash, length)
	if err != nil {
		return nil, fmt.Errorf("expand exported secret: %w", err)
	}

	return exportedSecret.AsSlice(), nil
}
