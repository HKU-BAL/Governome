// Copyright 2024 The University of Hong Kong, Department of Computer Science
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

func Queryuser_Boolen(Parameter tfhe.ParametersLiteral[uint32], user_name, rsid string, Readsymbol bool, Verifysymbol bool, option bool) {
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
		segkey1 = snarks.ReadSegKey(people, 1, params)
		segkey2 = snarks.ReadSegKey(people, 2, params)
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
			proof := snarks.ReadProof(people, i, 1)
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
	rsid := flag.String("rsid", "rs6053810", "Target Site in rsID")
	user_name := flag.String("user", "HG00096", "User Name in 1kGP")
	toy := flag.Bool("toy", true, "Whether using Toy Parameters")
	readsymbol := flag.Bool("read", false, "Whether read Data from file, not suitable for toy params")
	verifysymbol := flag.Bool("verify", false, "Whether verifying the proofs")
	Hosted := flag.Bool("precomputed", false, "Whether owner choose to precompute the access token")
	flag.Parse()

	if *toy {
		Queryuser_Boolen(auxiliary.ParamsToyBoolean, *user_name, *rsid, *readsymbol, *verifysymbol, *Hosted)
	} else {
		Queryuser_Boolen(tfhe.ParamsBinaryOriginal, *user_name, *rsid, *readsymbol, *verifysymbol, *Hosted)
	}
}
