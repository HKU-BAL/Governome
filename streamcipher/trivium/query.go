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
	"math"
	"math/big"

	"github.com/sp301415/tfhe-go/tfhe"
)

type Variant_TFHE struct {
	Rsid     [32]tfhe.LWECiphertext[uint32]
	Genotype [4]tfhe.LWECiphertext[uint32]
}

// Binary
type BigValue struct {
	Values     []int
	UpperBound int
}

// Binary
type BigValueCiphertext struct {
	Values     []tfhe.LWECiphertext[uint32]
	UpperBound int
}

// Float with 16-bit precision a.bcdefgh, [0, 2) a~0; h~16
type Fix16 struct {
	Values [16]tfhe.LWECiphertext[uint32]
}

// Binary, Encoding like int64
type Int64Ciphertext struct {
	Values [64]tfhe.LWECiphertext[uint32]
}

// Binary, Encoding like int72
type Int72Ciphertext struct {
	Values [72]tfhe.LWECiphertext[uint32]
}

// transfer BigValue to int
func BigValue2Int(v BigValue) int {
	res := 0
	for i := 0; i < len(v.Values); i++ {
		res += (v.Values[i] << i)
	}
	return res
}

// transfer int to BigValue
func Int2BigValue(u int) BigValue {
	var v BigValue
	if u == 0 {
		v.Values = make([]int, 1)
		v.Values[0] = 0
		v.UpperBound = 1
		return v
	}

	datalen := int(math.Floor(math.Log(float64(u))/math.Log(2.0))) + 1
	v.Values = make([]int, datalen)
	for i := 0; i < datalen; i++ {
		v.Values[i] = u & 1
		u = u >> 1
	}
	v.UpperBound = (1 << datalen) - 1
	return v
}

// transfer int to BigValue
func Int2BigValueWithUpperBound(u int, upperbound int) BigValue {

	var v BigValue

	datalen := int(math.Floor(math.Log(float64(upperbound))/math.Log(2.0))) + 1

	v.Values = make([]int, datalen)
	for i := 0; i < datalen; i++ {
		v.Values[i] = u & 1
		u = u >> 1
	}
	v.UpperBound = upperbound
	return v
}

// Encrypt a Variant to TFHE with public key
func Enc_Variant(v Variant, pk auxiliary.PublicKey_tfheb) (res Variant_TFHE) {
	for i := 0; i < 32; i++ {
		res.Rsid[i] = auxiliary.EncWithPublicKey_tfheb(uint32(v.Rsid[i]), pk)
	}
	for i := 0; i < 4; i++ {
		res.Genotype[i] = auxiliary.EncWithPublicKey_tfheb(uint32(v.Genotype[i]), pk)
	}
	return
}

// Get Raw Variant Ciphertext from Plaintext Without Error
func Enc_Variant_Raw(v Variant, params tfhe.Parameters[uint32]) (res Variant_TFHE) {
	for i := 0; i < 32; i++ {
		res.Rsid[i] = NewTFHECiphertext(v.Rsid[i], params)
	}
	for i := 0; i < 4; i++ {
		res.Genotype[i] = NewTFHECiphertext(v.Genotype[i], params)
	}
	return
}

// Decrypt Variant in TFHE ciphertext
func Dec_Variant(v Variant_TFHE, enc *tfhe.BinaryEncryptor) (res Variant) {
	for i := 0; i < 32; i++ {
		res.Rsid[i] = 0
		if enc.DecryptLWEBool(v.Rsid[i]) {
			res.Rsid[i] = 1
		}
	}
	for i := 0; i < 4; i++ {
		res.Genotype[i] = 0
		if enc.DecryptLWEBool(v.Genotype[i]) {
			res.Genotype[i] = 1
		}
	}
	return
}

// Xor operation between 2 variants in ciphertext
func (v1 *Variant_TFHE) Xor_Variant(v2 Variant_TFHE, eval *tfhe.BinaryEvaluator) (res Variant_TFHE) {
	for i := 0; i < 32; i++ {
		res.Rsid[i] = eval.XOR(v1.Rsid[i], v2.Rsid[i])
	}
	for i := 0; i < 4; i++ {
		res.Genotype[i] = eval.XOR(v1.Genotype[i], v2.Genotype[i])
	}
	return
}

// XNOR operation between 2 variants in ciphertext
func (v1 *Variant_TFHE) XNOR_Variant(v2 Variant_TFHE, eval *tfhe.BinaryEvaluator) (res Variant_TFHE) {
	for i := 0; i < 32; i++ {
		res.Rsid[i] = eval.XNOR(v1.Rsid[i], v2.Rsid[i])
	}
	for i := 0; i < 4; i++ {
		res.Genotype[i] = eval.XNOR(v1.Genotype[i], v2.Genotype[i])
	}
	return
}

// Judge whether 2 rsid are equal, return 0/1
func (v1 *Variant_TFHE) Judge_RSID(v2 Variant_TFHE, eval *tfhe.BinaryEvaluator) (res tfhe.LWECiphertext[uint32]) {
	res = eval.XNOR(v1.Rsid[0], v2.Rsid[0])
	for i := 1; i < 32; i++ {
		temp := eval.XNOR(v1.Rsid[i], v2.Rsid[i])
		res = eval.AND(res, temp)
	}
	return
}

// Compare whether 2 variants are equal
func Compare_Variant_TFHE(v1, v2 Variant_TFHE, eval *tfhe.BinaryEvaluator) BigValueCiphertext {
	v := v1.XNOR_Variant(v2, eval)
	res := eval.AND(v.Rsid[0], v.Rsid[1])
	for i := 2; i < 32; i++ {
		res = eval.AND(res, v.Rsid[i])
	}
	for i := 0; i < 4; i++ {
		res = eval.AND(res, v.Genotype[i])
	}
	var v_c BigValueCiphertext
	v_c.UpperBound = 1
	v_c.Values = make([]tfhe.LWECiphertext[uint32], 1)
	v_c.Values[0] = res
	return v_c
}

// Compare whether the rsid of 2 variants are equal, if so, genotype copy in v1
func Compare_RSID_TFHE(v1, v2 Variant_TFHE, eval *tfhe.BinaryEvaluator) (res [4]tfhe.LWECiphertext[uint32]) {
	c := v1.Judge_RSID(v2, eval)
	for i := 0; i < 4; i++ {
		res[i] = eval.AND(c, v1.Genotype[i])
	}
	return
}

// Compare two variants, if hit, get the number for different genotype of v1, 3 result: 0|0, 0|1 or 1|0, 1|1
func GenotypeFromTwoVariants(v1, v2 Variant_TFHE, eval *tfhe.BinaryEvaluator) (res [3]tfhe.LWECiphertext[uint32]) {
	c := v1.Judge_RSID(v2, eval)
	v := make([]Variant, 3)
	v[0].Genotype = Encode_Genotype(auxiliary.Genotype_s2i("0|1"))
	v[1].Genotype = Encode_Genotype(auxiliary.Genotype_s2i("1|0"))
	v[2].Genotype = Encode_Genotype(auxiliary.Genotype_s2i("1|1"))
	c_list := make([]tfhe.LWECiphertext[uint32], 3)
	for i := 0; i < 3; i++ {
		c_list[i] = NewTFHECiphertext(1, eval.Parameters)
	}

	for i := 0; i < 3; i++ {
		v_ct := Enc_Variant_Raw(v[i], eval.Parameters)
		for j := 0; j < 4; j++ {
			temp := eval.XNOR(v_ct.Genotype[j], v1.Genotype[j])
			c_list[i] = eval.AND(c_list[i], temp)
		}
	}

	res[0] = c
	res[1] = eval.OR(c_list[0], c_list[1])
	res[1] = eval.AND(res[1], c)
	res[2] = eval.AND(c_list[2], c)

	return
}

// Get a new BigValueCiphertext with value 0
func NewBigValueCiphertext(params tfhe.Parameters[uint32]) (v BigValueCiphertext) {
	v.UpperBound = 1
	v.Values = make([]tfhe.LWECiphertext[uint32], 1)
	v.Values[0] = tfhe.NewLWECiphertext[uint32](params)
	v.Values[0].Value[0] = auxiliary.ScaleConstant_tfheb(0)
	return
}

// Encryption BigValue to BigValueCiphertext
func Enc_BigValue(v BigValue, pk auxiliary.PublicKey_tfheb) (v_c BigValueCiphertext) {
	v_c.Values = make([]tfhe.LWECiphertext[uint32], len(v.Values))
	for i := 0; i < len(v_c.Values); i++ {
		v_c.Values[i] = auxiliary.EncWithPublicKey_tfheb(uint32(v.Values[i]), pk)
	}
	v_c.UpperBound = v.UpperBound
	return
}

// Decryption BigValueCiphertext to BigValue
func Dec_BigValue(v_c BigValueCiphertext, enc *tfhe.BinaryEncryptor) (v BigValue) {
	v.Values = make([]int, len(v_c.Values))
	for i := 0; i < len(v_c.Values); i++ {
		v.Values[i] = 0
		if enc.DecryptLWEBool(v_c.Values[i]) {
			v.Values[i] = 1
		}
	}
	v.UpperBound = v_c.UpperBound
	return
}

// Addition over two BigValueCiphertext
func AddBigValueCiphertext(v1, v2 BigValueCiphertext, eval *tfhe.BinaryEvaluator) (v BigValueCiphertext) {
	v.UpperBound = v1.UpperBound + v2.UpperBound
	datalen := int(math.Floor(math.Log(float64(v.UpperBound))/math.Log(2.0))) + 1

	v.Values = make([]tfhe.LWECiphertext[uint32], datalen)
	len1 := int(math.Floor(math.Log(float64(v1.UpperBound))/math.Log(2.0))) + 1
	len2 := int(math.Floor(math.Log(float64(v2.UpperBound))/math.Log(2.0))) + 1
	v.Values[0] = eval.XOR(v1.Values[0], v2.Values[0])
	c := eval.AND(v1.Values[0], v2.Values[0])
	for i := 1; i < datalen; i++ {
		a := tfhe.NewLWECiphertext[uint32](eval.Parameters)
		a.Value[0] += auxiliary.ScaleConstant_tfheb(0)
		b := tfhe.NewLWECiphertext[uint32](eval.Parameters)
		b.Value[0] += auxiliary.ScaleConstant_tfheb(0)
		if i < len1 {
			a = v1.Values[i]
		}
		if i < len2 {
			b = v2.Values[i]
		}
		v.Values[i] = eval.XOR(a, b)
		v.Values[i] = eval.XOR(v.Values[i], c)
		ab := eval.AND(a, b)
		ac := eval.AND(a, c)
		bc := eval.AND(b, c)
		c = eval.XOR(ab, ac)
		c = eval.XOR(c, bc)
	}
	return
}

// Set a BigValueCiphertext
func (v1 *BigValueCiphertext) SetBigValueCiphertext(v2 BigValueCiphertext) {
	v1.UpperBound = v2.UpperBound
	v1.Values = make([]tfhe.LWECiphertext[uint32], len(v2.Values))
	copy(v1.Values, v2.Values)
}

// Multiplication a BigValueCiphertext by 2
func Mul2(v BigValueCiphertext, params tfhe.Parameters[uint32]) (res BigValueCiphertext) {
	res.UpperBound = v.UpperBound << 1
	res.Values = make([]tfhe.LWECiphertext[uint32], len(v.Values)+1)
	res.Values[0] = tfhe.NewLWECiphertext[uint32](params)
	res.Values[0].Value[0] = auxiliary.ScaleConstant_tfheb(0)
	for i := 1; i < len(res.Values); i++ {
		res.Values[i] = v.Values[i-1]
	}
	return
}

// Multiplication over two BigValueCiphertext
func MulBigValueCiphertext(v1_input, v2_input BigValueCiphertext, eval *tfhe.BinaryEvaluator) (v BigValueCiphertext) {
	v.UpperBound = v1_input.UpperBound * v2_input.UpperBound

	datalen := int(math.Floor(math.Log(float64(v.UpperBound))/math.Log(2.0))) + 1

	v.Values = make([]tfhe.LWECiphertext[uint32], datalen)

	var v1, v2 BigValueCiphertext

	if v2_input.UpperBound < v1_input.UpperBound {
		v2 = v1_input
		v1 = v2_input
	} else {
		v1 = v1_input
		v2 = v2_input
	}

	len1 := int(math.Floor(math.Log(float64(v1.UpperBound))/math.Log(2.0))) + 1
	len2 := int(math.Floor(math.Log(float64(v2.UpperBound))/math.Log(2.0))) + 1
	bios := 0
	var temp, sum BigValueCiphertext
	for i := 0; i < len1; i++ {
		temp.SetBigValueCiphertext(v2)
		for j := 0; j < len2; j++ {
			temp.Values[j+bios] = eval.AND(temp.Values[j+bios], v1.Values[i])
		}
		if i == 0 {
			sum.SetBigValueCiphertext(temp)
		} else {
			sum = AddBigValueCiphertext(sum, temp, eval)
		}
		v2 = Mul2(v2, eval.Parameters)
		bios += 1
	}
	for i := 0; i < datalen; i++ {
		if i < len(sum.Values) {
			v.Values[i] = sum.Values[i]
		} else {
			v.Values[i] = tfhe.NewLWECiphertext[uint32](eval.Parameters)
			v.Values[i].Value[0] = auxiliary.ScaleConstant_tfheb(0)
		}
	}
	return
}

// Addition Over 2 Int72Ciphertext, v1 + v2 << bios, len2 bits of v2 is useful, up to maxlen bits of result is useful
func AddInt72CiphertextLimited(v1, v2 Int72Ciphertext, eval *tfhe.BinaryEvaluator, bios, maxlen, len2 int) (v Int72Ciphertext) {
	v.Values[bios] = eval.XOR(v1.Values[bios], v2.Values[0])
	c := eval.AND(v1.Values[bios], v2.Values[0])
	for i := bios + 1; i < bios+len2; i++ {
		v.Values[i] = eval.XOR(v1.Values[i], v2.Values[i-bios])
		v.Values[i] = eval.XOR(v.Values[i], c)
		ab := eval.AND(v1.Values[i], v2.Values[i-bios])
		ac := eval.AND(v1.Values[i], c)
		bc := eval.AND(v2.Values[i-bios], c)
		c = eval.XOR(ab, ac)
		c = eval.XOR(c, bc)
	}
	for i := bios + len2; i < maxlen; i++ {
		v.Values[i] = eval.XOR(c, v1.Values[i])
		c = eval.AND(c, v1.Values[i])
	}
	for i := 0; i < bios; i++ {
		v.Values[i] = v1.Values[i]
	}
	for i := maxlen; i < 72; i++ {
		v.Values[i] = v1.Values[i]
	}
	return
}

// Multiplication over a BigValueCiphertext and a int, the result is Int72Ciphertext
func MulIntAndBigValueCiphertextToInt72Ciphertext(v1 int, v2 BigValueCiphertext, eval *tfhe.BinaryEvaluator) (v Int72Ciphertext) {

	for i := 0; i < 72; i++ {
		v.Values[i] = tfhe.NewLWECiphertext[uint32](eval.Parameters)
		v.Values[i].Value[0] = auxiliary.ScaleConstant_tfheb(0)
	}

	var count uint
	count = 0
	lenv2 := int(math.Floor(math.Log(float64(v2.UpperBound))/math.Log(2.0))) + 1
	maxval := big.NewInt(0)
	Int72_v2 := BigValueCiphertextToInt72Ciphertext(v2, eval.Parameters)

	for v1 > 0 {
		if v1&1 == 0 {
			count += 1
			v1 = v1 >> 1
			continue
		}

		maxval.Add(maxval, big.NewInt(1).Lsh(big.NewInt(int64(v2.UpperBound)), count))
		maxlen := maxval.BitLen()

		v = AddInt72CiphertextLimited(v, Int72_v2, eval, int(count), maxlen, lenv2)

		count += 1
		v1 = v1 >> 1
	}

	return
}

// Transfer a BigValueCiphertext to Int64Ciphertext
func BigValueCiphertextToInt64Ciphertext(v BigValueCiphertext, params tfhe.Parameters[uint32]) (res Int64Ciphertext) {
	length := int(math.Floor(math.Log(float64(v.UpperBound))/math.Log(2.0))) + 1
	if length > 64 {
		length = 64
	}
	for i := 0; i < length; i++ {
		res.Values[i] = v.Values[i]
	}

	for i := length; i < 64; i++ {
		res.Values[i] = tfhe.NewLWECiphertext[uint32](params)
		res.Values[i].Value[0] = auxiliary.ScaleConstant_tfheb(0)
	}
	return
}

// Transfer a BigValueCiphertext to Int72Ciphertext
func BigValueCiphertextToInt72Ciphertext(v BigValueCiphertext, params tfhe.Parameters[uint32]) (res Int72Ciphertext) {
	var length int
	if v.UpperBound > 0 {
		length = int(math.Floor(math.Log(float64(v.UpperBound))/math.Log(2.0))) + 1
	} else {
		length = 72
	}

	if length > 72 {
		length = 72
	}
	for i := 0; i < length; i++ {
		res.Values[i] = v.Values[i]
	}

	for i := length; i < 72; i++ {
		res.Values[i] = tfhe.NewLWECiphertext[uint32](params)
		res.Values[i].Value[0] = auxiliary.ScaleConstant_tfheb(0)
	}
	return
}

// Addition Over 2 Int64Ciphertext
func AddInt64Ciphertext(v1, v2 Int64Ciphertext, eval *tfhe.BinaryEvaluator) (v Int64Ciphertext) {
	v.Values[0] = eval.XOR(v1.Values[0], v2.Values[0])
	c := eval.AND(v1.Values[0], v2.Values[0])
	for i := 1; i < 64; i++ {
		v.Values[i] = eval.XOR(v1.Values[i], v2.Values[i])
		v.Values[i] = eval.XOR(v.Values[i], c)
		ab := eval.AND(v1.Values[i], v2.Values[i])
		ac := eval.AND(v1.Values[i], c)
		bc := eval.AND(v2.Values[i], c)
		c = eval.XOR(ab, ac)
		c = eval.XOR(c, bc)
	}
	return
}

// Addition Over 2 Int72Ciphertext
func AddInt72Ciphertext(v1, v2 Int72Ciphertext, eval *tfhe.BinaryEvaluator) (v Int72Ciphertext) {
	v.Values[0] = eval.XOR(v1.Values[0], v2.Values[0])
	c := eval.AND(v1.Values[0], v2.Values[0])
	for i := 1; i < 72; i++ {
		v.Values[i] = eval.XOR(v1.Values[i], v2.Values[i])
		v.Values[i] = eval.XOR(v.Values[i], c)
		ab := eval.AND(v1.Values[i], v2.Values[i])
		ac := eval.AND(v1.Values[i], c)
		bc := eval.AND(v2.Values[i], c)
		c = eval.XOR(ab, ac)
		c = eval.XOR(c, bc)
	}
	return
}

// Sub Over 2 Int72Ciphertext
func SubInt72Ciphertext(v1, v2 Int72Ciphertext, eval *tfhe.BinaryEvaluator) (v Int72Ciphertext) {
	new_v2 := NegInt72Ciphertext(v2, eval)
	v = AddInt72Ciphertext(v1, new_v2, eval)
	return
}

// Reverse all bits
func BitReverseInt64Ciphertext(v Int64Ciphertext, eval *tfhe.BinaryEvaluator) (res Int64Ciphertext) {
	for i := 0; i < 64; i++ {
		res.Values[i] = eval.NOT(v.Values[i])
	}
	return
}

// Reverse all bits
func BitReverseInt72Ciphertext(v Int72Ciphertext, eval *tfhe.BinaryEvaluator) (res Int72Ciphertext) {
	for i := 0; i < 72; i++ {
		res.Values[i] = eval.NOT(v.Values[i])
	}
	return
}

// return x + 1
func Add1_Int64Ciphertext(v Int64Ciphertext, eval *tfhe.BinaryEvaluator) (res Int64Ciphertext) {
	c := tfhe.NewLWECiphertext[uint32](eval.Parameters)
	c.Value[0] = auxiliary.ScaleConstant_tfheb(1)
	for i := 0; i < 64; i++ {
		res.Values[i] = eval.XOR(v.Values[i], c)
		c = eval.AND(c, v.Values[i])
	}
	return
}

// return x + 1
func Add1_Int72Ciphertext(v Int72Ciphertext, eval *tfhe.BinaryEvaluator) (res Int72Ciphertext) {
	c := tfhe.NewLWECiphertext[uint32](eval.Parameters)
	c.Value[0] = auxiliary.ScaleConstant_tfheb(1)
	for i := 0; i < 72; i++ {
		res.Values[i] = eval.XOR(v.Values[i], c)
		c = eval.AND(c, v.Values[i])
	}
	return
}

// return -x
func NegInt64Ciphertext(v Int64Ciphertext, eval *tfhe.BinaryEvaluator) (res Int64Ciphertext) {
	temp := BitReverseInt64Ciphertext(v, eval)
	res = Add1_Int64Ciphertext(temp, eval)
	return
}

// return -x
func NegInt72Ciphertext(v Int72Ciphertext, eval *tfhe.BinaryEvaluator) (res Int72Ciphertext) {
	temp := BitReverseInt72Ciphertext(v, eval)
	res = Add1_Int72Ciphertext(temp, eval)
	return
}

// Decryption Int64Ciphertext to int
func Dec_Int64Ciphertext(v_c Int64Ciphertext, enc *tfhe.BinaryEncryptor) (v int) {
	v = 0
	for i := 0; i < 64; i++ {
		temp := 0
		if enc.DecryptLWEBool(v_c.Values[i]) {
			temp = 1
		}
		v += temp << i
	}
	return
}

// Decryption Int72Ciphertext to int
func Dec_Int72Ciphertext(v_c Int72Ciphertext, enc *tfhe.BinaryEncryptor) (v *big.Int) {
	v = big.NewInt(0)
	for i := 0; i < 72; i++ {
		temp := 0
		if enc.DecryptLWEBool(v_c.Values[i]) {
			temp = 1
		}
		if i == 71 {
			v.Sub(v, big.NewInt(1).Lsh(big.NewInt(int64(temp)), uint(i)))
			break
		}

		v.Add(v, big.NewInt(1).Lsh(big.NewInt(int64(temp)), uint(i)))

	}
	return
}

// query a single individual, and return BigValueCiphertext 0/1
// func queryIndiv(Data []Variant_TFHE, QueryVariant_TFHE Variant_TFHE, eval *tfhe.BinaryEvaluator) (v BigValueCiphertext) {
// 	eval = eval.ShallowCopy()
// 	v = Compare_Variant_TFHE(QueryVariant_TFHE, Data[0], eval)
// 	for i := 1; i < len(Data); i++ {
// 		temp := Compare_Variant_TFHE(QueryVariant_TFHE, Data[i], eval)
// 		v = AddBigValueCiphertext(v, temp, eval)
// 	}
// 	v.UpperBound = 1
// 	return
// }

// Decrypt Stream ciphertext with TFHE key
func DecCiphertextBySegKey(encrypted_data []Variant_TFHE, triv *Trivium_TFHE, eval *tfhe.BinaryEvaluator) (decrypted_data []Variant_TFHE) {
	eval = eval.ShallowCopy()
	decrypted_data = make([]Variant_TFHE, len(encrypted_data))

	Stream := make([]Variant_TFHE, len(encrypted_data))

	for i := 0; i < len(encrypted_data); i++ {
		for j := 0; j < 32; j++ {
			Stream[i].Rsid[j] = triv.Genbit(eval)
		}
		for j := 0; j < 4; j++ {
			Stream[i].Genotype[j] = triv.Genbit(eval)
		}
		decrypted_data[i] = encrypted_data[i].Xor_Variant(Stream[i], eval)
	}

	return
}

// Get a new uint32 LWECiphertext
func NewTFHECiphertext(val int, params tfhe.Parameters[uint32]) (res tfhe.LWECiphertext[uint32]) {
	res = tfhe.NewLWECiphertext[uint32](params)
	res.Value[0] = auxiliary.ScaleConstant_tfheb(uint32(val))
	return
}

// Return 1 if a = 1, b = 0
func Test10(a, b tfhe.LWECiphertext[uint32], eval *tfhe.BinaryEvaluator) (res tfhe.LWECiphertext[uint32]) {
	val0 := NewTFHECiphertext(0, eval.Parameters)
	val1 := NewTFHECiphertext(1, eval.Parameters)
	testa := eval.XNOR(val1, a)
	testb := eval.XNOR(val0, b)
	res = eval.AND(testa, testb)
	return
}

// Return 1 if a = 1, b = 1
func Test11(a, b tfhe.LWECiphertext[uint32], eval *tfhe.BinaryEvaluator) (res tfhe.LWECiphertext[uint32]) {
	val1 := NewTFHECiphertext(1, eval.Parameters)
	testa := eval.XNOR(val1, a)
	testb := eval.XNOR(val1, b)
	res = eval.AND(testa, testb)
	return
}

// Get Fix16 Value in [0.75, 1.5) from Int72Ciphertext a = res * 2 ^ (72-lambda)
func GetFix16FromInt72Ciphertext(v Int72Ciphertext, eval *tfhe.BinaryEvaluator) (res Fix16, lambda BigValueCiphertext) {
	for i := 0; i < 16; i++ {
		res.Values[i] = NewTFHECiphertext(0, eval.Parameters)
	}

	lambda = NewBigValueCiphertext(eval.Parameters)

	var larger_int89 [89]tfhe.LWECiphertext[uint32]
	for i := 0; i < 16; i++ {
		larger_int89[i] = NewTFHECiphertext(0, eval.Parameters)
	}
	for i := 16; i < 88; i++ {
		larger_int89[i] = v.Values[i-16]
	}
	larger_int89[88] = NewTFHECiphertext(0, eval.Parameters)

	// After found the bits, set it to 0, so And not make sense
	founded := NewTFHECiphertext(1, eval.Parameters)

	for i := 87; i >= 16; i-- {
		// whether the current 2 bits fits, then & founded -- fit10: 10, fit11: 11
		fit10 := Test10(larger_int89[i], larger_int89[i-1], eval)
		fit11 := Test11(larger_int89[i], larger_int89[i-1], eval)
		fit10 = eval.AND(fit10, founded)
		fit11 = eval.AND(fit11, founded)
		for j := 0; j < 16; j++ {
			temp := eval.AND(fit10, larger_int89[i-j])
			res.Values[j] = eval.OR(temp, res.Values[j])
		}
		for j := 0; j < 16; j++ {
			temp := eval.AND(fit11, larger_int89[i-j+1])
			res.Values[j] = eval.OR(temp, res.Values[j])
		}
		fit := eval.OR(fit10, fit11)
		founded = eval.AND(founded, eval.NOT(fit))
		addfounded := NewBigValueCiphertext(eval.Parameters)
		addfounded.Values[0] = founded
		extra_val := NewBigValueCiphertext(eval.Parameters)
		extra_val.Values[0] = fit10
		lambda = AddBigValueCiphertext(lambda, addfounded, eval)
		lambda = AddBigValueCiphertext(lambda, extra_val, eval)
	}

	return
}

// Addition Over 2 Fix16, should make sure it not exceed 2
func AddFix16(v1, v2 Fix16, eval *tfhe.BinaryEvaluator) (v Fix16) {
	v.Values[15] = eval.XOR(v1.Values[15], v2.Values[15])
	c := eval.AND(v1.Values[15], v2.Values[15])
	for i := 14; i >= 0; i-- {
		v.Values[i] = eval.XOR(v1.Values[i], v2.Values[i])
		v.Values[i] = eval.XOR(v.Values[i], c)
		if i > 0 {
			ab := eval.AND(v1.Values[i], v2.Values[i])
			ac := eval.AND(v1.Values[i], c)
			bc := eval.AND(v2.Values[i], c)
			c = eval.XOR(ab, ac)
			c = eval.XOR(c, bc)
		}
	}
	return
}

// Multiplication Over 2 Fix16, should make sure it not exceed 2
func MulFix16(v1, v2 Fix16, eval *tfhe.BinaryEvaluator) (v Fix16) {
	for i := 0; i < 16; i++ {
		v.Values[i] = NewTFHECiphertext(0, eval.Parameters)
	}
	for i := 0; i < 16; i++ {
		var temp Fix16
		for j := 0; j < i; j++ {
			temp.Values[j] = NewTFHECiphertext(0, eval.Parameters)
		}
		for j := i; j < 16; j++ {
			temp.Values[j] = eval.AND(v1.Values[i], v2.Values[j-i])
		}
		v = AddFix16(v, temp, eval)
	}
	return
}

// BitReverse In Fix16
func BitReverseFix16(v Fix16, eval *tfhe.BinaryEvaluator) (res Fix16) {
	for i := 0; i < 16; i++ {
		res.Values[i] = eval.NOT(v.Values[i])
	}
	return
}

// 2 - x <=> -x
func NegFix16(v Fix16, eval *tfhe.BinaryEvaluator) (res Fix16) {
	res = BitReverseFix16(v, eval)
	val1 := NewTFHECiphertext(1, eval.Parameters)
	res.Values[15] = eval.XOR(val1, res.Values[15])
	c := eval.AND(val1, res.Values[15])
	for i := 14; i >= 0; i-- {
		res.Values[i] = eval.XOR(res.Values[i], c)
		if i > 0 {
			c = eval.AND(c, res.Values[i])
		}
	}
	return
}

// Sub Over 2 Fix16, should make sure it is positive
func SubFix16(v1, v2 Fix16, eval *tfhe.BinaryEvaluator) (v Fix16) {
	negv2 := NegFix16(v2, eval)
	v = AddFix16(v1, negv2, eval)
	return
}

// 1 / b in Fix16, here b should be in [0.75, 1.5)
func ReverseFix16(b Fix16, eval *tfhe.BinaryEvaluator) (res Fix16) {
	y := NegFix16(b, eval)
	by := MulFix16(b, y, eval)
	var val1Fix16 Fix16
	val1Fix16.Values[0] = NewTFHECiphertext(1, eval.Parameters)
	for i := 1; i < 16; i++ {
		val1Fix16.Values[i] = NewTFHECiphertext(0, eval.Parameters)
	}
	// e = 1 - by; 1/b = y(1+e)(1+e^2)
	e := SubFix16(val1Fix16, by, eval)
	e2 := MulFix16(e, e, eval)
	e4 := MulFix16(e2, e2, eval)
	eadd1 := e
	eadd1.Values[0] = eval.XOR(eadd1.Values[0], val1Fix16.Values[0])
	e2add1 := e2
	e2add1.Values[0] = eval.XOR(e2add1.Values[0], val1Fix16.Values[0])
	e4add1 := e4
	e4add1.Values[0] = eval.XOR(e4add1.Values[0], val1Fix16.Values[0])
	res = MulFix16(eadd1, e2add1, eval)
	res = MulFix16(res, e4add1, eval)
	res = MulFix16(res, y, eval)
	return
}

// a / b in Fix16, here b should be in [0.75, 1.5)
func DivFix16(a, b Fix16, eval *tfhe.BinaryEvaluator) (res Fix16) {
	rev_b := ReverseFix16(b, eval)
	res = MulFix16(a, rev_b, eval)
	return
}

// Encrypt a value in [0.75, 1.5) to Fix16
func EncFix16(a float64, pk auxiliary.PublicKey_tfheb) (res Fix16) {
	temp := uint32(math.Round(a * 128 * 256))
	for i := 15; i >= 0; i-- {
		v := temp & 1
		res.Values[i] = auxiliary.EncWithPublicKey_tfheb(v, pk)
		temp = temp >> 1
	}
	return
}

// Decrypt a Fix16 Value to float64
func DecFix16(a Fix16, enc *tfhe.BinaryEncryptor) (res float64) {
	res = 0
	for i := 0; i < 16; i++ {
		temp := 1 << i
		if enc.DecryptLWEBool(a.Values[i]) {
			res += (1 / float64(temp))
		}
	}
	return
}

// Divide 2 positive Int72Ciphertext a/b, result in a Fix16 and a extra exp value
func DivInt72Ciphertext(a, b Int72Ciphertext, eval *tfhe.BinaryEvaluator) (bit_res Fix16, exp_res Int72Ciphertext) {
	bit_a, la := GetFix16FromInt72Ciphertext(a, eval)
	bit_b, lb := GetFix16FromInt72Ciphertext(b, eval)
	new_bit := DivFix16(bit_a, bit_b, eval)
	// condition: 1 : new_bit < 1, then new_bit *= 2, exp - 1 <=> la + 1
	condition := eval.NOT(new_bit.Values[0])
	con_val := NewBigValueCiphertext(eval.Parameters)
	con_val.Values[0] = condition
	la = AddBigValueCiphertext(la, con_val, eval)
	exp_a := BigValueCiphertextToInt72Ciphertext(la, eval.Parameters)
	exp_b := BigValueCiphertextToInt72Ciphertext(lb, eval.Parameters)
	exp_res = SubInt72Ciphertext(exp_b, exp_a, eval)
	var fix1, fix2 Fix16
	fix1.Values[0] = new_bit.Values[0]
	fix2.Values[15] = NewTFHECiphertext(0, eval.Parameters)

	for i := 1; i < 16; i++ {
		fix1.Values[i] = eval.AND(new_bit.Values[0], new_bit.Values[i])
		fix2.Values[i-1] = eval.AND(condition, new_bit.Values[i])
	}

	for i := 0; i < 16; i++ {
		bit_res.Values[i] = eval.OR(fix1.Values[i], fix2.Values[i])
	}

	return
}

// Decrypt the result for a division
func DecDivResult(bit_res Fix16, exp_res Int72Ciphertext, enc *tfhe.BinaryEncryptor) float64 {
	temp := DecFix16(bit_res, enc)
	exp := Dec_Int72Ciphertext(exp_res, enc).Int64()
	res := math.Exp2(float64(exp))
	res = res * temp
	return res
}
