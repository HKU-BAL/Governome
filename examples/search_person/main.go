package main

import (
	"Governome/applications"
	"Governome/auxiliary"
	"Governome/snarks"
	"Governome/streamcipher/trivium"
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/sp301415/tfhe-go/tfhe"
)

func Boolean_Search(query_target applications.CODIS, Parameter tfhe.ParametersLiteral[uint32], Readsymbol bool, Verifysymbol bool, option bool, dicpath string) {
	params := Parameter.Compile()

	enc := tfhe.NewBinaryEncryptor(params)

	if Readsymbol {
		trivium.ReadSK(enc)
	}

	eval := tfhe.NewBinaryEvaluator(params, enc.GenEvaluationKeyParallel())

	pk := auxiliary.GenLWEPublicKey_tfheb(enc)
	if Readsymbol {
		pk = trivium.ReadPK(params)
	}

	Indiv := auxiliary.ReadIndividuals()

	DataLen := len(Indiv)

	segkey1 := make([][]tfhe.LWECiphertext[uint32], DataLen)
	segkey2 := make([][]tfhe.LWECiphertext[uint32], DataLen)

	if Readsymbol {
		for i := 0; i < DataLen; i++ {
			segkey1[i] = snarks.ReadSegKey(Indiv[i], 1, params)
			segkey2[i] = snarks.ReadSegKey(Indiv[i], 2, params)
		}
	} else {
		segkey1, segkey2 = trivium.GetSegKeyFromPKForAppID(pk, applications.App_id_SearchPerson, 1, Indiv, option)
	}

	if Verifysymbol {
		ccs := snarks.GenorReadR1CS(false, option)
		_, VerifyKey := snarks.GenorReadSetup(ccs, false, option)
		for i := 0; i < DataLen; i++ {
			keyhash1, keyhash2 := trivium.ReadKeyhash(Indiv[i], 1, option)
			var publicWitness1, publicWitness2 []witness.Witness
			proof1 := snarks.ReadProof(Indiv[i], 1, 1)
			proof2 := snarks.ReadProof(Indiv[i], 2, 1)
			if option {
				publicWitness1 = snarks.ConstructpublicWitnessWithSegKeyHosted(keyhash1, segkey1[i])
				publicWitness2 = snarks.ConstructpublicWitnessWithSegKeyHosted(keyhash2, segkey2[i])
			} else {
				publicWitness1 = snarks.ConstructpublicWitnessWithSegKeyDefault(applications.App_id_SearchPerson, keyhash1, segkey1[i])
				publicWitness2 = snarks.ConstructpublicWitnessWithSegKeyDefault(applications.App_id_SearchPerson, keyhash2, segkey2[i])
			}

			for k := 0; k < len(proof1); k++ {
				err := groth16.Verify(proof1[k], VerifyKey, publicWitness1[k])
				if err != nil {
					log.Fatalf("Verification failed, err is %+v", err)
				}
			}
			for k := 0; k < len(proof2); k++ {
				err := groth16.Verify(proof2[k], VerifyKey, publicWitness2[k])
				if err != nil {
					log.Fatalf("Verification failed, err is %+v", err)
				}
			}
		}
	}

	QueryCODIS := trivium.Enc_CODIS(trivium.Encode_Single_CODIS(query_target), pk)

	res := trivium.SearchPerson(QueryCODIS, segkey1, segkey2, eval, DataLen, 1, option)
	hitsymbol := false
	for i := 0; i < len(res); i++ {
		if enc.DecryptLWEBool(res[i]) {
			fmt.Println(strconv.Itoa(i), " Hit!")
			hitsymbol = true
		}
	}
	if !hitsymbol {
		fmt.Println("Query not hit!")
	}
}

func main() {

	toy := flag.Bool("Toy", true, "Whether using Toy Parameters")
	GroundTruthID := flag.Int("GroundTruth", 0, "GroundTruthID")
	readsymbol := flag.Bool("ReadKey", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("Verify", false, "Whether verifying the proofs")
	Hosted := flag.Bool("Hosted", false, "Whether to use hosted mode")
	Path := flag.String("path", "../../..", "Target FilePath")
	flag.Parse()

	var query_target applications.CODIS
	if *GroundTruthID >= 0 && *GroundTruthID < 2504 {
		query_target = applications.GetCODISbyID(*GroundTruthID)
	} else {
		query_target = applications.GenRandomCODIS()
	}

	if *toy {
		Boolean_Search(query_target, auxiliary.ParamsToyBoolean, *readsymbol, *verifysymbol, *Hosted, *Path)
	} else {
		Boolean_Search(query_target, tfhe.ParamsBinaryOriginal, *readsymbol, *verifysymbol, *Hosted, *Path)
	}

}
