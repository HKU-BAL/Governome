package main

import (
	"Governome/applications"
	"Governome/auxiliary"
	"Governome/streamcipher/trivium"
	"flag"

	"github.com/sp301415/tfhe-go/tfhe"
)

func main() {

	toy := flag.Bool("toy", true, "Whether using Toy Parameters")
	segsymbol := flag.Bool("seg", false, "Whether to preprocess the data to segments")
	codissymbol := flag.Bool("str", false, "Whether to generate the str data")
	codisencsymbol := flag.Bool("strenc", false, "Whether to encrypt the str data")
	keysymbol := flag.Bool("genkey", false, "Whether to generate the keys")
	Hosted := flag.Bool("precomputed", false, "Whether owner choose to precompute the access token")
	Path := flag.String("path", "../../..", "Root FilePath")

	auxiliary.SavePath(*Path)

	flag.Parse()

	if *codissymbol {
		applications.GenAndSaveCODISData()
	}

	if *keysymbol {
		if *toy {
			trivium.GenAndSaveKey(auxiliary.ParamsToyBoolean.Compile())
		} else {
			trivium.GenAndSaveKey(tfhe.ParamsBinaryOriginal.Compile())
		}
	}
	if *codisencsymbol {
		trivium.EncAndSaveCODIS_Trivium(*Hosted)
	}
	if *segsymbol {
		trivium.EncryptAndSaveData(*Hosted)
	}

}
