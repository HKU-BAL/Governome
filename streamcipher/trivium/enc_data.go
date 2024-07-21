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

package trivium

import (
	"Governome/auxiliary"
	"math/big"
	"strconv"
)

type Variant struct {
	Rsid     [32]int
	Genotype [4]int
}

// Encryption or Decryption a Variant in Plaintext
func (v1 *Variant) XOR_Stream(v2 Variant) (res Variant) {
	for i := 0; i < 32; i++ {
		res.Rsid[i] = v1.Rsid[i] ^ v2.Rsid[i]
	}
	for i := 0; i < 4; i++ {
		res.Genotype[i] = v1.Genotype[i] ^ v2.Genotype[i]
	}
	return
}

// Compare two Variants to judge whether they are equal
func (v1 *Variant) Compare_Variant(v2 Variant) bool {
	res := true
	for i := 0; i < 32; i++ {
		temp := (v1.Rsid[i] == v2.Rsid[i])
		res = (res && temp)
	}
	for i := 0; i < 4; i++ {
		temp := (v1.Genotype[i] == v2.Genotype[i])
		res = (res && temp)
	}

	return res
}

// Encode rsID to Variant format
func Encode_rsID(rsid int) (res [32]int) {
	for i := 0; i < 32; i++ {
		res[i] = rsid & 1
		rsid = rsid >> 1
	}
	return
}

// Encode Genotype to Variant format
func Encode_Genotype(genotype int) (res [4]int) {
	for i := 0; i < 4; i++ {
		res[i] = genotype & 1
		genotype = genotype >> 1
	}
	return
}

// Decode the rsID array
func Decode_rsID(rsid [32]int) int {
	res := 0
	for i := 0; i < 32; i++ {
		res += (1 << i) * rsid[i]
	}
	return res
}

// Decode the genotype array
func Decode_Genotype(genotype [4]int) int {
	res := 0
	for i := 0; i < 4; i++ {
		res += (1 << i) * genotype[i]
	}
	return res
}

// Encode the Variant to our struct
func Encode_Variant(rsid int, genotype int) (v Variant) {
	v.Genotype = Encode_Genotype(genotype)
	v.Rsid = Encode_rsID(rsid)
	return
}

// Decode the variant into origin string format
func (v *Variant) Decode2String() string {
	r := auxiliary.RsID_i2s(Decode_rsID(v.Rsid))
	g := auxiliary.Genotype_i2s(Decode_Genotype(v.Genotype))
	return r + " " + g
}

// Divide the origin data of an individual into Segments
func DivideIntoSegments(people auxiliary.People) (Encoded_Variants [][]Variant) {

	RSIDs, GTs := auxiliary.ReadPlaintext_data(people)
	Encoded_Variants = make([][]Variant, auxiliary.Seg_num)
	for i := 0; i < len(RSIDs); i++ {
		var temp_variant Variant
		temp_variant.Genotype = Encode_Genotype(GTs[i])
		temp_variant.Rsid = Encode_rsID(RSIDs[i])
		index := auxiliary.SegmentID(people, RSIDs[i], auxiliary.Seg_num)
		Encoded_Variants[index] = append(Encoded_Variants[index], temp_variant)
	}

	for i := 0; i < auxiliary.Seg_num; i++ {
		if len(Encoded_Variants[i]) < auxiliary.Minimal_Blocksize {
			newEV := make([]Variant, auxiliary.Minimal_Blocksize)
			for j := 0; j < auxiliary.Minimal_Blocksize; j++ {
				if j < len(Encoded_Variants[i]) {
					newEV[j] = Encoded_Variants[i][j]
				} else {
					var v Variant
					newEV[j] = v
				}
			}
			Encoded_Variants[i] = newEV

		}
	}
	return
}

// Transfer encrypted segments to string form that can be saved
func SegmentToStrings(seg_data [][]Variant, keyhash1, keyhash2 []byte, Indivname string) [][]string {
	string_data := make([][]string, len(seg_data)*2+1)
	string_data[0] = make([]string, 3)
	string_data[0][0] = Indivname
	string_data[0][1] = "Key hash1: " + big.NewInt(1).SetBytes(keyhash1).String()
	string_data[0][2] = "Key hash2: " + big.NewInt(1).SetBytes(keyhash2).String()
	for i := 0; i < len(seg_data); i++ {
		string_data[2*i+1] = make([]string, 2)
		string_data[2*i+1][0] = "Segment" + strconv.Itoa(i)
		string_data[2*i+1][1] = "Variants amount: " + strconv.Itoa(len(seg_data[i]))
		// string_data[2*i+1][2] = "Full Hash1: " + big.NewInt(1).SetBytes(full_hash1[i]).String()
		// string_data[2*i+1][3] = "Full Hash2: " + big.NewInt(1).SetBytes(full_hash2[i]).String()
		string_data[2*i+2] = make([]string, len(seg_data[i]))
		for j := 0; j < len(seg_data[i]); j++ {
			string_data[2*i+2][j] = seg_data[i][j].Decode2String()
		}
	}
	return string_data
}

// Encrypt the data with keyinfo, with option, if option == true, Hosted mode, else, each segment a key
func Data_Enc(RawData [][]Variant, keyinfo1, keyinfo2 []byte, option bool) [][]Variant {
	Stream := make([][]Variant, auxiliary.Seg_num)

	StreamKey1 := make([]int, 80)
	StreamKey2 := make([]int, 80)

	if option {
		StreamKey1 = GenKeyHostedMode(keyinfo1, 1)
	} else {
		StreamKey2 = GenKeyHostedMode(keyinfo2, 1)
	}

	for i := 0; i < auxiliary.Seg_num; i++ {
		if !option {
			StreamKey1 = GenSegmentKey(keyinfo1, i, 1)
		} else {
			StreamKey2 = GenSegmentKey(keyinfo2, i, 1)
		}

		iv := GenIVHostedMode(i)

		StreamKey := make([]int, 80)
		for j := 0; j < 80; j++ {
			StreamKey[j] = StreamKey1[j] ^ StreamKey2[j]
		}

		var triv Trivium
		triv.Init(StreamKey, iv)

		Stream[i] = make([]Variant, len(RawData[i]))

		for j := 0; j < len(RawData[i]); j++ {
			for k := 0; k < 32; k++ {
				newbit := triv.Genbit()
				Stream[i][j].Rsid[k] = newbit
			}
			for k := 0; k < 4; k++ {
				newbit := triv.Genbit()
				Stream[i][j].Genotype[k] = newbit
			}
		}
	}

	Ciphertext := make([][]Variant, auxiliary.Seg_num)
	for i := 0; i < auxiliary.Seg_num; i++ {
		Ciphertext[i] = make([]Variant, len(RawData[i]))
		for j := 0; j < len(RawData[i]); j++ {
			Ciphertext[i][j] = RawData[i][j].XOR_Stream(Stream[i][j])
		}
	}

	return Ciphertext
}

// Decrypt a segment with keyinfo
func Seg_Dec(RawData []Variant, keyinfo []byte, segID int, batch_size int) []Variant {
	StreamKey := GenSegmentKey(keyinfo, segID, batch_size)
	iv := make([]int, 80)
	var triv Trivium
	triv.Init(StreamKey, iv)
	Stream := make([]Variant, len(RawData))

	for i := 0; i < len(RawData); i++ {
		for j := 0; j < 32; j++ {
			newbit := triv.Genbit()
			Stream[i].Rsid[j] = newbit
		}
		for j := 0; j < 4; j++ {
			newbit := triv.Genbit()
			Stream[i].Genotype[j] = newbit
		}
	}

	Plaintext := make([]Variant, len(RawData))
	for i := 0; i < len(RawData); i++ {
		Plaintext[i] = RawData[i].XOR_Stream(Stream[i])
	}

	return Plaintext
}
