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

func QueryTrivium(Parameter tfhe.ParametersLiteral[uint32], rsid string, population string, Readsymbol bool, Verifysymbol bool) {
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
			segID := auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num)
			segkey1[i] = snarks.ReadSegKey(Indiv[i], 1, segID, 1, params)
			segkey2[i] = snarks.ReadSegKey(Indiv[i], 2, segID, 1, params)
		}
	} else {
		pk := auxiliary.GenLWEPublicKey_tfheb(enc)
		segkey1, segkey2 = trivium.GetSegKeyFromPK(pk, auxiliary.RsID_s2i(rsid), 1, Indiv[0:DataLen])
	}

	if Verifysymbol {
		var circuit snarks.TriviumCircuit
		ccs := snarks.GenorReadR1CS(circuit)
		_, VerifyKey := snarks.GenorReadSetup(ccs)
		for i := 0; i < DataLen; i++ {
			segID := auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num)
			keyhash1, keyhash2 := trivium.ReadKeyhash(Indiv[i], 1)
			proof1 := snarks.ReadProof(Indiv[i], 1, segID, 1)
			publicWitness1 := snarks.ConstructpublicWitnessWithct(segID, keyhash1, segkey1[i])
			proof2 := snarks.ReadProof(Indiv[i], 2, segID, 1)
			publicWitness2 := snarks.ConstructpublicWitnessWithct(segID, keyhash2, segkey2[i])
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

	res := trivium.QueryCiphertext(auxiliary.RsID_s2i(rsid), segkey1, segkey2, eval, 1, Indiv[0:DataLen])
	count00 := trivium.BigValue2Int(trivium.Dec_BigValue(res[0], enc))
	count01 := trivium.BigValue2Int(trivium.Dec_BigValue(res[1], enc))
	count11 := trivium.BigValue2Int(trivium.Dec_BigValue(res[2], enc))

	fmt.Println(strconv.Itoa(int(count00)) + " Individuals has Variant " + rsid + " 0|0")
	fmt.Println(strconv.Itoa(int(count01)) + " Individuals has Variant " + rsid + " 0|1")
	fmt.Println(strconv.Itoa(int(count11)) + " Individuals has Variant " + rsid + " 1|1")
}

func main() {

	rsid := flag.String("Rsid", "rs6053810", "Target Site")
	population := flag.String("Population", "EUR", "Population, in 'AFR', 'AMR', 'EAS', 'EUR', 'SAS'")
	toy := flag.Bool("Toy", true, "Whether using Toy Parameters")
	readsymbol := flag.Bool("ReadKey", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("Verify", false, "Whether verifying the proofs")
	flag.Parse()

	if *toy {
		QueryTrivium(auxiliary.ParamsToyBoolean, *rsid, *population, *readsymbol, *verifysymbol)
	} else {
		QueryTrivium(tfhe.ParamsBinaryOriginal, *rsid, *population, *readsymbol, *verifysymbol)
	}

}
