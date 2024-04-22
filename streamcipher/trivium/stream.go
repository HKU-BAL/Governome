package trivium

import (
	"Governome/auxiliary"
	"fmt"

	"github.com/sp301415/tfhe-go/tfhe"
)

type Trivium struct {
	L [288]int
}

type Trivium_TFHE struct {
	L [288]tfhe.LWECiphertext[uint32]
}

// Generate a stream bit
func (triv *Trivium) Genbit() int {
	t1 := triv.L[65] ^ triv.L[92]
	t2 := triv.L[161] ^ triv.L[176]
	t3 := triv.L[242] ^ triv.L[287]
	z := t1 ^ t2 ^ t3

	t1 = t1 ^ (triv.L[90] & triv.L[91]) ^ triv.L[170]
	t2 = t2 ^ (triv.L[174] & triv.L[175]) ^ triv.L[263]
	t3 = t3 ^ (triv.L[285] & triv.L[286]) ^ triv.L[68]

	for i := 287; i > 0; i-- {
		triv.L[i] = triv.L[i-1]
	}

	triv.L[0] = t3
	triv.L[93] = t1
	triv.L[177] = t2

	return z
}

// Generate a stream bit in TFHE ciphertext
func (triv *Trivium_TFHE) Genbit(eval *tfhe.BinaryEvaluator) tfhe.LWECiphertext[uint32] {

	t1 := eval.XOR(triv.L[65], triv.L[92])
	t2 := eval.XOR(triv.L[161], triv.L[176])
	t3 := eval.XOR(triv.L[242], triv.L[287])
	z := eval.XOR(t1, t2)
	z = eval.XOR(z, t3)

	temp1 := eval.AND(triv.L[90], triv.L[91])
	t1 = eval.XOR(t1, temp1)
	t1 = eval.XOR(t1, triv.L[170])

	temp2 := eval.AND(triv.L[174], triv.L[175])
	t2 = eval.XOR(t2, temp2)
	t2 = eval.XOR(t2, triv.L[263])

	temp3 := eval.AND(triv.L[285], triv.L[286])
	t3 = eval.XOR(t3, temp3)
	t3 = eval.XOR(t3, triv.L[68])

	for i := 287; i > 0; i-- {
		triv.L[i] = triv.L[i-1]
	}

	triv.L[0] = t3
	triv.L[93] = t1
	triv.L[177] = t2

	return z
}

// Set params from plaintext trivium
func (triv_tfheb *Trivium_TFHE) Set(pk auxiliary.PublicKey_tfheb, triv Trivium) {
	for i := 0; i < 288; i++ {
		triv_tfheb.L[i] = auxiliary.EncWithPublicKey_tfheb(uint32(triv.L[i]), pk)
	}
}

// Init the key for Trivium
func (triv *Trivium) Init(key []int, iv []int) {
	if len(key) != 80 || len(iv) != 80 {
		fmt.Println("Invalid Input!")
		return
	}
	for i := 0; i < 80; i++ {
		triv.L[i] = key[i]
		triv.L[i+93] = iv[i]
	}
	triv.L[285] = 1
	triv.L[286] = 1
	triv.L[287] = 1

	for i := 0; i < 1152; i++ {
		triv.Genbit()
	}
}

// Init in ciphertext
func (triv *Trivium_TFHE) Init(key1, key2 []tfhe.LWECiphertext[uint32], eval *tfhe.BinaryEvaluator, iv []int) {
	if len(key1) != 80 || len(key2) != 80 || len(iv) != 80 {
		fmt.Println("Invalid Input!")
		return
	}
	for i := 0; i < 288; i++ {
		triv.L[i] = tfhe.NewLWECiphertext[uint32](eval.Parameters)
		triv.L[i].Value[0] += auxiliary.ScaleConstant_tfheb(0)
	}

	for i := 0; i < 80; i++ {
		triv.L[i] = eval.XOR(key1[i], key2[i])
		triv.L[i+93] = NewTFHECiphertext(iv[i], eval.Parameters)
	}
	triv.L[285] = NewTFHECiphertext(1, eval.Parameters)
	triv.L[286] = NewTFHECiphertext(1, eval.Parameters)
	triv.L[287] = NewTFHECiphertext(1, eval.Parameters)

	for i := 0; i < 1152; i++ {
		triv.Genbit(eval)
	}
}
