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

func GWAS(Parameter tfhe.ParametersLiteral[uint32], rsid string, population string, Readsymbol bool, Verifysymbol bool) {
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

	WholeIndivs := auxiliary.ReadIndividuals()
	Indiv, _, Phenotype, _ := applications.ReadPhenotype(WholeIndivs, population)

	Phenotype_Ciphertext := make([]trivium.BigValueCiphertext, len(Indiv))
	for i := 0; i < len(Phenotype_Ciphertext); i++ {
		Phenotype_Ciphertext[i] = trivium.Enc_BigValue(trivium.Int2BigValueWithUpperBound(Phenotype[i], 1), pk)
	}

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

	bit_res, exp_res := trivium.GWASBool(auxiliary.RsID_s2i(rsid), segkey1, segkey2, eval, 1, Indiv, Phenotype_Ciphertext)

	val := trivium.DecDivResult(bit_res, exp_res, enc)
	p := trivium.GWASResultToPValue(val, len(Indiv))

	fmt.Printf("The P value is (%s)\n", strconv.FormatFloat(p, 'f', -1, 64))
}

func main() {

	rsid := flag.String("Rsid", "rs6053810", "Target Site")
	population := flag.String("Population", "EUR", "Population")
	toy := flag.Bool("Toy", true, "Whether using Toy Parameters")
	readsymbol := flag.Bool("ReadKey", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("Verify", false, "Whether verifying the proofs")
	flag.Parse()

	if *toy {
		GWAS(auxiliary.ParamsToyBoolean, *rsid, *population, *readsymbol, *verifysymbol)
	} else {
		GWAS(tfhe.ParamsBinaryOriginal, *rsid, *population, *readsymbol, *verifysymbol)
	}

}
