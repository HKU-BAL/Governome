package main

import (
	"Governome/auxiliary"
	"Governome/snarks"
	"Governome/streamcipher/trivium"
	"flag"
	"fmt"
	"log"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/sp301415/tfhe-go/tfhe"
)

func Queryuser_Trivium(Parameter tfhe.ParametersLiteral[uint32], user_name, rsid string, Readsymbol bool, Verifysymbol bool, option bool) {

	var gt [4]int

	params := Parameter.Compile()

	enc := tfhe.NewBinaryEncryptor(params)
	if Readsymbol {
		trivium.ReadSK(enc)
	}

	eval := tfhe.NewBinaryEvaluator(params, enc.GenEvaluationKeyParallel())

	var segkey1, segkey2 []tfhe.LWECiphertext[uint32]

	Indivs := auxiliary.ReadIndividuals()
	var people auxiliary.People
	for i := 0; i < len(Indivs); i++ {
		if Indivs[i].Name == user_name {
			people = Indivs[i]
			break
		}
	}

	if Readsymbol {
		segID := auxiliary.SegmentID(people, auxiliary.RsID_s2i(rsid), auxiliary.Seg_num)
		segkey1 = snarks.ReadSegKey(people, 1, segID, 1, params, option)
		segkey2 = snarks.ReadSegKey(people, 2, segID, 1, params, option)
	} else {
		Indiv := make([]auxiliary.People, 1)
		Indiv[0] = people
		pk := auxiliary.GenLWEPublicKey_tfheb(enc)
		key1, key2 := trivium.GetSegKeyFromPK(pk, auxiliary.RsID_s2i(rsid), 1, Indiv, option)
		segkey1 = key1[0]
		segkey2 = key2[0]
	}

	if Verifysymbol {
		segID := auxiliary.SegmentID(people, auxiliary.RsID_s2i(rsid), auxiliary.Seg_num)
		keyhash1, keyhash2 := trivium.ReadKeyhash(people, 1, option)
		ccs := snarks.GenorReadR1CS(false, option)
		_, VerifyKey := snarks.GenorReadSetup(ccs, false, option)
		for i := 1; i < 3; i++ {
			proof := snarks.ReadProof(people, i, segID, 1, option)
			var publicWitness []witness.Witness
			if i == 1 {
				if option {
					publicWitness = snarks.ConstructpublicWitnessWithSegKeyHosted(keyhash1, segkey1)
				} else {
					publicWitness = snarks.ConstructpublicWitnessWithSegKeyDefault(segID, keyhash1, segkey1)
				}
			} else {
				if option {
					publicWitness = snarks.ConstructpublicWitnessWithSegKeyHosted(keyhash2, segkey2)
				} else {
					publicWitness = snarks.ConstructpublicWitnessWithSegKeyDefault(segID, keyhash2, segkey2)
				}
			}
			for k := 0; k < len(proof); k++ {
				err := groth16.Verify(proof[k], VerifyKey, publicWitness[k])
				if err != nil {
					log.Fatalf("Verification failed, err is %+v", err)
				}
			}
		}

	}

	gt_ct := trivium.Userquery(people, auxiliary.RsID_s2i(rsid), segkey1, segkey2, 1, eval, option)
	for i := 0; i < 4; i++ {
		if enc.DecryptLWEBool(gt_ct[i]) {
			gt[i] = 1
		}
	}

	fmt.Println(auxiliary.Genotype_i2s(trivium.Decode_Genotype(gt)))
}

func main() {
	rsid := flag.String("Rsid", "rs6053810", "Target Site")
	user_name := flag.String("User", "HG00096", "Data Owner Nickname")
	toy := flag.Bool("Toy", true, "Whether using Toy Parameters")
	readsymbol := flag.Bool("ReadKey", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("Verify", false, "Whether verifying the proofs")
	Hosted := flag.Bool("Hosted", false, "Whether to use hosted mode")
	flag.Parse()

	if *toy {
		Queryuser_Trivium(auxiliary.ParamsToyBoolean, *user_name, *rsid, *readsymbol, *verifysymbol, *Hosted)
	} else {
		Queryuser_Trivium(tfhe.ParamsBinaryOriginal, *user_name, *rsid, *readsymbol, *verifysymbol, *Hosted)
	}
}
