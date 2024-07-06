package auxiliary

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
)

const Curve = ecc.BN254
const Mimchashcurve = hash.MIMC_BN254
const Seg_num = 96000
const Minimal_Blocksize = 20
