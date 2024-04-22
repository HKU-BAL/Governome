package main

import (
	"Governome/applications"
	"Governome/auxiliary"
	"Governome/streamcipher/trivium"
	"flag"

	"github.com/sp301415/tfhe-go/tfhe"
)

func main() {

	toy := flag.Bool("Toy", false, "Whether using Toy Parameters")
	segsymbol := flag.Bool("Segment", false, "Whether to preprocess the data to segments")
	codissymbol := flag.Bool("Codis", false, "Whether to generate the codis data")
	codisencsymbol := flag.Bool("CodisEnc", false, "Whether to encrypt the codis data")
	keysymbol := flag.Bool("GenKey", false, "Whether to generate the keys")
	batchsize := flag.Int("BlockSize", 1, "BlockSize for the keys for zk-snarks")

	flag.Parse()

	if *codissymbol {
		applications.GenAndSaveData()
	}

	if *keysymbol {
		if *toy {
			trivium.GenAndSaveKey(auxiliary.ParamsToyBoolean.Compile())
		} else {
			trivium.GenAndSaveKey(tfhe.ParamsBinaryOriginal.Compile())
		}
	}
	if *codisencsymbol {
		trivium.EncAndSaveCODIS_Trivium(*batchsize)
	}
	if *segsymbol {
		trivium.EncryptAndSaveData(*batchsize)
	}

}
