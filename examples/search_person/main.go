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
	"github.com/sp301415/tfhe-go/tfhe"
)

func Trivium_Search(query_target applications.CODIS, Parameter tfhe.ParametersLiteral[uint32], DataLen int, Readsymbol bool, Verifysymbol bool) {
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

	Indiv := auxiliary.ReadIndividuals()[0:DataLen]

	segkey1 := make([][]tfhe.LWECiphertext[uint32], DataLen)
	segkey2 := make([][]tfhe.LWECiphertext[uint32], DataLen)

	if Readsymbol {
		for i := 0; i < DataLen; i++ {
			segkey1[i] = snarks.ReadSegKey(Indiv[i], 1, applications.App_id_SearchPerson, 1, params)
			segkey2[i] = snarks.ReadSegKey(Indiv[i], 2, applications.App_id_SearchPerson, 1, params)
		}
	} else {
		segkey1, segkey2 = trivium.GetSegKeyFromPKForAppID(pk, applications.App_id_SearchPerson, 1, Indiv[0:DataLen])
	}

	if Verifysymbol {
		var circuit snarks.TriviumCircuit
		ccs := snarks.GenorReadR1CS(circuit)
		_, VerifyKey := snarks.GenorReadSetup(ccs)
		for i := 0; i < DataLen; i++ {
			keyhash1, keyhash2 := trivium.ReadKeyhash(Indiv[i], 1)
			proof1 := snarks.ReadProof(Indiv[i], 1, applications.App_id_SearchPerson, 1)
			publicWitness1 := snarks.ConstructpublicWitnessWithct(applications.App_id_SearchPerson, keyhash1, segkey1[i])
			proof2 := snarks.ReadProof(Indiv[i], 2, applications.App_id_SearchPerson, 1)
			publicWitness2 := snarks.ConstructpublicWitnessWithct(applications.App_id_SearchPerson, keyhash2, segkey2[i])
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

	res := trivium.SearchPerson(QueryCODIS, segkey1, segkey2, eval, DataLen, 1)
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

	datalen := flag.Int("DataLen", 2504, "Participate Number")
	toy := flag.Bool("Toy", true, "Whether using Toy Parameters")
	GroundTruthID := flag.Int("GroundTruth", 0, "GroundTruthID")
	readsymbol := flag.Bool("ReadKey", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("Verify", false, "Whether verifying the proofs")
	flag.Parse()

	var query_target applications.CODIS
	if *GroundTruthID >= 0 && *GroundTruthID < 2504 {
		query_target = applications.GetCODISbyID(*GroundTruthID)
	} else {
		query_target = applications.GenRandomCODIS()
	}

	if *datalen >= 2504 || *datalen < 0 {
		fmt.Println("Invalid Data Length!")
		return
	}

	if *datalen == 0 {
		*datalen = 2504
	}

	if *toy {
		Trivium_Search(query_target, auxiliary.ParamsToyBoolean, *datalen, *readsymbol, *verifysymbol)

	} else {
		Trivium_Search(query_target, tfhe.ParamsBinaryOriginal, *datalen, *readsymbol, *verifysymbol)
	}

}
