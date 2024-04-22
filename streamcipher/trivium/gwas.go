package trivium

import (
	"Governome/auxiliary"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/sp301415/tfhe-go/tfhe"
	"gonum.org/v1/gonum/stat/distuv"
)

// gcd of two int
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Calculate t value from p value
func PtoT(p float64, df int) float64 {
	tDist := distuv.StudentsT{
		Mu:    0,
		Sigma: 1,
		Nu:    float64(df),
	}
	t := tDist.Quantile(1 - p/2)
	return t
}

// Calculate p value from t value
func TtoP(t float64, df int) float64 {
	tDist := distuv.StudentsT{
		Mu:    0,
		Sigma: 1,
		Nu:    float64(df),
	}

	p := (1 - tDist.CDF(t)) * 2
	return p
}

// Transfer the result to p value
func GWASResultToPValue(s float64, n int) float64 {
	t2 := float64(n-2) / float64(n)
	t2 = t2 * s
	t := math.Sqrt(t2)
	return TtoP(t, 2)
}

// Round t^2 to nearest rational number q/p
func ParsetValue(t float64, precision int) (p, q int) {
	modulus := 1 << precision
	t2 := t * t * float64(modulus)
	q = int(math.Round(t2))
	g := gcd(q, modulus)
	p = modulus / g
	q = q / g
	return
}

func GWAS_raw(Genotype []int, Phenotype []int, n int) float64 {
	var y, a, x, b, c float64
	x, y, a, b = 0, 0, 0, 0
	for i := 0; i < n; i++ {
		x = x + float64(Genotype[i])
		y = y + float64(Phenotype[i])
		a = a + float64(Genotype[i]*Genotype[i])
		b = b + float64(Genotype[i]*Phenotype[i])
		c = c + float64(Phenotype[i]*Phenotype[i])
	}

	alpha := ((y * a) - (x * b)) / (float64(n)*a - x*x)
	beta := ((float64(n) * b) - (x * y)) / (float64(n)*a - x*x)

	x_average := x / float64(n)
	var delta, x_res float64
	delta, x_res = 0, 0
	for i := 0; i < n; i++ {
		delta += (alpha + beta*float64(Genotype[i]) - float64(Phenotype[i])) * (alpha + beta*float64(Genotype[i]) - float64(Phenotype[i]))
		x_res += (float64(Genotype[i]) - x_average) * (float64(Genotype[i]) - x_average)
	}
	s2 := delta / x_res
	s2 = s2 / float64(n-2)

	s := math.Sqrt(s2)

	t := beta / s

	return TtoP(math.Abs(t), 2)
}

// GWAS Over Plaintext
func GWAS_Plaintext(Genotype []int, Phenotype []int, n int, p_threshold float64) int {
	t_threshold := PtoT(p_threshold, 2)
	p, q := ParsetValue(t_threshold, 4)
	G_2 := make([]int, n)
	P_2 := make([]int, n)
	GP := make([]int, n)
	for i := 0; i < n; i++ {
		G_2[i] = Genotype[i] * Genotype[i]
		P_2[i] = Phenotype[i] * Phenotype[i]
		GP[i] = Genotype[i] * Phenotype[i]
	}
	x, y, a, b, c := 0, 0, 0, 0, 0
	for i := 0; i < n; i++ {
		x += Genotype[i]
		y += Phenotype[i]
		a += G_2[i]
		b += GP[i]
		c += P_2[i]
	}

	ab := a * b
	ab2 := ab * b
	ay := a * y
	a2y2 := ay * ay
	bx := b * x
	b2x2 := bx * bx
	abxy := ay * bx
	x2 := x * x
	x2y := x2 * y
	x4y2 := x2y * x2y
	ax2y2 := ay * x2y
	bx3y := bx * x2y
	ac := a * c
	a2c := a * ac
	acx2 := ac * x2
	cx2 := c * x2
	cx4 := cx2 * x2

	sum := big.NewInt(0)
	temp := big.NewInt(1).Mul(big.NewInt(int64(p*(n-2)*n*n*n+q*n*n*n)), big.NewInt(int64(ab2)))
	sum.Add(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(2*p*(n-2)*n*n+2*q*n*n)), big.NewInt(int64(abxy)))
	sum.Sub(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(p*(n-2)*n-q*n)), big.NewInt(int64(ax2y2)))
	sum.Add(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(p*(n-2)*n*n+q*n*n)), big.NewInt(int64(b2x2)))
	sum.Sub(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(2*p*(n-2)*n+2*q*n)), big.NewInt(int64(bx3y)))
	sum.Add(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(p*(n-2))), big.NewInt(int64(x4y2)))
	sum.Sub(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(q*n*n)), big.NewInt(int64(a2y2)))
	sum.Add(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(q*n*n*n)), big.NewInt(int64(a2c)))
	sum.Sub(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(2*q*n*n)), big.NewInt(int64(acx2)))
	sum.Add(sum, temp)

	temp = big.NewInt(1).Mul(big.NewInt(int64(q*n)), big.NewInt(int64(cx4)))
	sum.Sub(sum, temp)

	if sum.Sign() == -1 {
		return 0
	}

	return 1

}

// Calculate s^2 for a s in 0, 1, 2
func SquareSNP(s BigValueCiphertext, params tfhe.Parameters[uint32]) (res BigValueCiphertext) {
	res.UpperBound = 4
	res.Values = make([]tfhe.LWECiphertext[uint32], 3)
	res.Values[2] = s.Values[1]
	res.Values[0] = s.Values[0]
	res.Values[1] = tfhe.NewLWECiphertext[uint32](params)
	res.Values[1].Value[0] = auxiliary.ScaleConstant_tfheb(0)
	return
}

// GWAS Over Ciphertext
func GWAS_Ciphertext(Genotype []BigValueCiphertext, Phenotype []BigValueCiphertext, n int, p_threshold float64, eval *tfhe.BinaryEvaluator) tfhe.LWECiphertext[uint32] {
	t_threshold := PtoT(p_threshold, 2)
	p, q := ParsetValue(t_threshold, 4)
	G_2 := make([]BigValueCiphertext, n)
	P_2 := make([]BigValueCiphertext, n)
	GP := make([]BigValueCiphertext, n)

	now := time.Now()
	for i := 0; i < n; i++ {
		G_2[i] = SquareSNP(Genotype[i], eval.Parameters)
		P_2[i] = MulBigValueCiphertext(Phenotype[i], Phenotype[i], eval)
		GP[i] = MulBigValueCiphertext(Genotype[i], Phenotype[i], eval)
	}
	fmt.Printf("Finish Square in (%s)\n", time.Since(now))
	now = time.Now()

	x := NewBigValueCiphertext(eval.Parameters)
	y := NewBigValueCiphertext(eval.Parameters)
	a := NewBigValueCiphertext(eval.Parameters)
	b := NewBigValueCiphertext(eval.Parameters)
	c := NewBigValueCiphertext(eval.Parameters)

	for i := 0; i < n; i++ {
		x = AddBigValueCiphertext(x, Genotype[i], eval)
		y = AddBigValueCiphertext(y, Phenotype[i], eval)
		a = AddBigValueCiphertext(a, G_2[i], eval)
		b = AddBigValueCiphertext(b, GP[i], eval)
		c = AddBigValueCiphertext(c, P_2[i], eval)
	}

	fmt.Printf("Finish Addition in (%s)\n", time.Since(now))
	now = time.Now()

	ab := MulBigValueCiphertext(a, b, eval)
	ab2 := MulBigValueCiphertext(ab, b, eval)
	ay := MulBigValueCiphertext(a, y, eval)
	a2y2 := MulBigValueCiphertext(ay, ay, eval)
	bx := MulBigValueCiphertext(b, x, eval)
	b2x2 := MulBigValueCiphertext(bx, bx, eval)
	abxy := MulBigValueCiphertext(ay, bx, eval)
	x2 := MulBigValueCiphertext(x, x, eval)
	x2y := MulBigValueCiphertext(x2, y, eval)
	x4y2 := MulBigValueCiphertext(x2y, x2y, eval)
	ax2y2 := MulBigValueCiphertext(ay, x2y, eval)
	bx3y := MulBigValueCiphertext(bx, x2y, eval)
	ac := MulBigValueCiphertext(a, c, eval)
	a2c := MulBigValueCiphertext(a, ac, eval)
	acx2 := MulBigValueCiphertext(ac, x2, eval)
	cx2 := MulBigValueCiphertext(c, x2, eval)
	cx4 := MulBigValueCiphertext(cx2, x2, eval)

	sum := MulIntAndBigValueCiphertextToInt72Ciphertext(p*(n-2)*n*n*n+q*n*n*n, ab2, eval)

	temp := MulIntAndBigValueCiphertextToInt72Ciphertext(2*p*(n-2)*n*n+2*q*n*n, abxy, eval)
	sum = SubInt72Ciphertext(sum, temp, eval)

	// sig!!!!
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(p*(n-2)*n-q*n, ax2y2, eval)
	sum = AddInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(p*(n-2)*n*n+q*n*n, b2x2, eval)
	sum = SubInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(2*p*(n-2)*n+2*q*n, bx3y, eval)
	sum = AddInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(p*(n-2), x4y2, eval)
	sum = SubInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(q*n*n, a2y2, eval)
	sum = AddInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(q*n*n*n, a2c, eval)
	sum = SubInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(2*q*n*n, acx2, eval)
	sum = AddInt72Ciphertext(sum, temp, eval)

	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(q*n, cx4, eval)
	sum = SubInt72Ciphertext(sum, temp, eval)

	fmt.Printf("Finish Multiplication in (%s)\n", time.Since(now))

	return sum.Values[71]

}

// GWAS Over Plaintext, result is t^2 * n / (n-2)
func GWASWithPValue_Plaintext(Genotype []int, Phenotype []int, n int) float64 {
	G_2 := make([]int, n)
	P_2 := make([]int, n)
	GP := make([]int, n)
	for i := 0; i < n; i++ {
		G_2[i] = Genotype[i] * Genotype[i]
		P_2[i] = Phenotype[i] * Phenotype[i]
		GP[i] = Genotype[i] * Phenotype[i]
	}
	x, y, a, b, c := 0, 0, 0, 0, 0
	for i := 0; i < n; i++ {
		x += Genotype[i]
		y += Phenotype[i]
		a += G_2[i]
		b += GP[i]
		c += P_2[i]
	}

	ab := a * b
	ab2 := ab * b
	ay := a * y
	a2y2 := ay * ay
	bx := b * x
	b2x2 := bx * bx
	abxy := ay * bx
	x2 := x * x
	x2y := x2 * y
	x4y2 := x2y * x2y
	ax2y2 := ay * x2y
	bx3y := bx * x2y
	ac := a * c
	a2c := a * ac
	acx2 := ac * x2
	cx2 := c * x2
	cx4 := cx2 * x2

	p, q := 0, 0

	p += n * n * n * ab2
	p -= 2 * n * n * abxy
	p += n * ax2y2
	p -= n * n * b2x2
	p += 2 * n * bx3y
	p -= x4y2

	q += n * b2x2
	q -= n * a2y2
	q -= n * n * ab2
	q += ax2y2
	q += n * n * a2c
	q -= 2 * n * acx2
	q += cx4
	q += 2 * n * abxy
	q -= 2 * bx3y

	return float64(p) / float64(q)

}

// GWAS Over Ciphertext, result is t^2 * n / (n-2)
func GWASWithPValue_Ciphertext(Genotype []BigValueCiphertext, Phenotype []BigValueCiphertext, n int, eval *tfhe.BinaryEvaluator) (bit_res Fix16, exp_res Int72Ciphertext) {
	G_2 := make([]BigValueCiphertext, n)
	P_2 := make([]BigValueCiphertext, n)
	GP := make([]BigValueCiphertext, n)

	// now := time.Now()
	for i := 0; i < n; i++ {
		G_2[i] = SquareSNP(Genotype[i], eval.Parameters)
		P_2[i] = MulBigValueCiphertext(Phenotype[i], Phenotype[i], eval)
		GP[i] = MulBigValueCiphertext(Genotype[i], Phenotype[i], eval)
	}
	// fmt.Printf("Finish Square in (%s)\n", time.Since(now))
	// now = time.Now()

	x := NewBigValueCiphertext(eval.Parameters)
	y := NewBigValueCiphertext(eval.Parameters)
	a := NewBigValueCiphertext(eval.Parameters)
	b := NewBigValueCiphertext(eval.Parameters)
	c := NewBigValueCiphertext(eval.Parameters)

	for i := 0; i < n; i++ {
		x = AddBigValueCiphertext(x, Genotype[i], eval)
		y = AddBigValueCiphertext(y, Phenotype[i], eval)
		a = AddBigValueCiphertext(a, G_2[i], eval)
		b = AddBigValueCiphertext(b, GP[i], eval)
		c = AddBigValueCiphertext(c, P_2[i], eval)
	}

	// fmt.Printf("Finish Addition in (%s)\n", time.Since(now))
	// now = time.Now()

	ab := MulBigValueCiphertext(a, b, eval)
	ab2 := MulBigValueCiphertext(ab, b, eval)
	ay := MulBigValueCiphertext(a, y, eval)
	a2y2 := MulBigValueCiphertext(ay, ay, eval)
	bx := MulBigValueCiphertext(b, x, eval)
	b2x2 := MulBigValueCiphertext(bx, bx, eval)
	abxy := MulBigValueCiphertext(ay, bx, eval)
	x2 := MulBigValueCiphertext(x, x, eval)
	x2y := MulBigValueCiphertext(x2, y, eval)
	x4y2 := MulBigValueCiphertext(x2y, x2y, eval)
	ax2y2 := MulBigValueCiphertext(ay, x2y, eval)
	bx3y := MulBigValueCiphertext(bx, x2y, eval)
	ac := MulBigValueCiphertext(a, c, eval)
	a2c := MulBigValueCiphertext(a, ac, eval)
	acx2 := MulBigValueCiphertext(ac, x2, eval)
	cx2 := MulBigValueCiphertext(c, x2, eval)
	cx4 := MulBigValueCiphertext(cx2, x2, eval)

	p := MulIntAndBigValueCiphertextToInt72Ciphertext(n*n*n, ab2, eval)
	temp := MulIntAndBigValueCiphertextToInt72Ciphertext(2*n*n, abxy, eval)
	p = SubInt72Ciphertext(p, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(n, ax2y2, eval)
	p = AddInt72Ciphertext(p, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(n*n, b2x2, eval)
	p = SubInt72Ciphertext(p, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(2*n, bx3y, eval)
	p = AddInt72Ciphertext(p, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(1, x4y2, eval)
	p = SubInt72Ciphertext(p, temp, eval)

	q := MulIntAndBigValueCiphertextToInt72Ciphertext(n, b2x2, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(n, a2y2, eval)
	q = SubInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(n*n, ab2, eval)
	q = SubInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(1, ax2y2, eval)
	q = AddInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(n*n, a2c, eval)
	q = AddInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(2*n, acx2, eval)
	q = SubInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(1, cx4, eval)
	q = AddInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(2*n, abxy, eval)
	q = AddInt72Ciphertext(q, temp, eval)
	temp = MulIntAndBigValueCiphertextToInt72Ciphertext(2, bx3y, eval)
	q = SubInt72Ciphertext(q, temp, eval)

	// fmt.Printf("Finish Multiplication in (%s)\n", time.Since(now))
	// now = time.Now()

	bit_res, exp_res = DivInt72Ciphertext(p, q, eval)
	// fmt.Printf("Finish Division in (%s)\n", time.Since(now))

	return

}
