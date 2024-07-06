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

func QueryBoolean(Parameter tfhe.ParametersLiteral[uint32], rsid string, population string, Readsymbol bool, Verifysymbol bool, option bool) {
	params := Parameter.Compile()

	enc := tfhe.NewBinaryEncryptor(params)
	if Readsymbol {
		trivium.ReadSK(enc)
	}

	eval := tfhe.NewBinaryEvaluator(params, enc.GenEvaluationKeyParallel())

	WholeIndivs := auxiliary.ReadIndividuals()
	Indiv, _, _, _ := applications.ReadPhenotype(WholeIndivs, population)
	DataLen := len(Indiv)

	segkey1 := make([][]tfhe.LWECiphertext[uint32], DataLen)
	segkey2 := make([][]tfhe.LWECiphertext[uint32], DataLen)

	if Readsymbol {
		for i := 0; i < DataLen; i++ {
			segkey1[i] = snarks.ReadSegKey(Indiv[i], 1, params)
			segkey2[i] = snarks.ReadSegKey(Indiv[i], 2, params)
		}
	} else {
		pk := auxiliary.GenLWEPublicKey_tfheb(enc)
		segkey1, segkey2 = trivium.GetSegKeyFromPK(pk, auxiliary.RsID_s2i(rsid), 1, Indiv, option)
	}

	if Verifysymbol {
		ccs := snarks.GenorReadR1CS(false, option)
		_, VerifyKey := snarks.GenorReadSetup(ccs, false, option)
		for i := 0; i < DataLen; i++ {
			segID := auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num)
			keyhash1, keyhash2 := trivium.ReadKeyhash(Indiv[i], 1, option)
			proof1 := snarks.ReadProof(Indiv[i], 1, 1)
			proof2 := snarks.ReadProof(Indiv[i], 2, 1)
			var publicWitness1, publicWitness2 []witness.Witness
			if option {
				publicWitness1 = snarks.ConstructpublicWitnessWithSegKeyHosted(keyhash1, segkey1[i])
				publicWitness2 = snarks.ConstructpublicWitnessWithSegKeyDefault(segID, keyhash2, segkey2[i])
			} else {
				publicWitness1 = snarks.ConstructpublicWitnessWithSegKeyDefault(segID, keyhash1, segkey1[i])
				publicWitness2 = snarks.ConstructpublicWitnessWithSegKeyHosted(keyhash2, segkey2[i])
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

	res := trivium.QueryCiphertext(auxiliary.RsID_s2i(rsid), segkey1, segkey2, eval, 1, Indiv, option)
	count00 := trivium.BigValue2Int(trivium.Dec_BigValue(res[0], enc))
	count01 := trivium.BigValue2Int(trivium.Dec_BigValue(res[1], enc))
	count11 := trivium.BigValue2Int(trivium.Dec_BigValue(res[2], enc))

	fmt.Println(strconv.Itoa(int(count00)) + " Individuals has Variant " + rsid + " 0|0")
	fmt.Println(strconv.Itoa(int(count01)) + " Individuals has Variant " + rsid + " 0|1")
	fmt.Println(strconv.Itoa(int(count11)) + " Individuals has Variant " + rsid + " 1|1")
}

func main() {

	rsid := flag.String("Rsid", "rs6053810", "Target Site")
	population := flag.String("Population", "ALL", "Population, in 'AFR', 'AMR', 'EAS', 'EUR', 'SAS', 'ALL'")
	toy := flag.Bool("Toy", true, "Whether using Toy Parameters")
	readsymbol := flag.Bool("ReadKey", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("Verify", false, "Whether verifying the proofs")
	Hosted := flag.Bool("Hosted", false, "Whether to use hosted mode")

	flag.Parse()

	if *toy {
		QueryBoolean(auxiliary.ParamsToyBoolean, *rsid, *population, *readsymbol, *verifysymbol, *Hosted)
	} else {
		QueryBoolean(tfhe.ParamsBinaryOriginal, *rsid, *population, *readsymbol, *verifysymbol, *Hosted)
	}

}
