package govector

import (
	"fmt"
	"testing"

	"github.com/bmizerany/assert"
)

func TestVectors(t *testing.T) {
	x, err := AsVector([]int{2, 2, 2, 4, 2, 5})
	assert.Equal(t, nil, err, "Error casting integer array to vector")

	w, err := AsVector([]float64{1.0, 1.0, 1.0, 1.0, 1.0, 4.0})
	assert.Equal(t, nil, err, "Error casting float64 array to vector")

	q, err := AsVector([]float64{0.05, 0.95})
	assert.Equal(t, nil, err, "Error casing float64 array to vector")

	d_x := x.Diff()
	d_w := w.Diff()

	max := x.Max()
	assert.Equal(t, 5.0, max, "Error calculating max")

	min := x.Min()
	assert.Equal(t, 2.0, min, "Error calculating min")

	empirical := x.Ecdf()

	percentile := empirical(2.4)
	assert.Equal(t, 2.0/3.0, percentile, "Error in CDF calculation")

	_, err = d_x.WeightedMean(d_w)
	assert.Equal(t, nil, err, "Error calculating weighted mean")

	_ = x.Quantiles(q)

	cumsum := x.Cumsum()
	assert.Equal(t, Vector{2, 4, 6, 10, 12, 17}, cumsum, "Error calculating cumulative sum")

	ranks := x.Rank()
	assert.Equal(t, Vector{3, 0, 0, 4, 0, 5}, ranks, "Error calculating ranks")

	shuffled := x.Shuffle()
	assert.Equal(t, x.Len(), shuffled.Len(), "Error shuffling vector")

	y, err := AsVector([]int{-2, 2, -1, 4, 2, 5})
	assert.Equal(t, nil, err, "Error casting negative integer array to vector")

	abs := y.Abs()
	assert.Equal(t, Vector{2, 2, 1, 4, 2, 5}, abs, "Error finding absolute values")

	_ = x.Apply(empirical)

	n := x.Len()
	x.Push(50)
	assert.Equal(t, n+1, x.Len(), "Error appending value to vector")

	xw := Join(x, w)
	assert.Equal(t, x.Len()+w.Len(), xw.Len(), "Error joining vectors")

	filtered := xw.Filter(func(x float64) bool {
		if x < 10 {
			return false
		}
		return true
	})
	assert.Equal(t, 12, len(filtered), "Error filtering vector")

	z, err := AsVector([]int{0, 2, 4, 6, 8, 10, 12, 14, 16, 18})
	assert.Equal(t, nil, err)

	smoothed := z.Smooth(0, 0)
	assert.Equal(t, z, smoothed)

	smoothed = z.Smooth(1, 1)
	expected := Vector{1, 2, 4, 6, 8, 10, 12, 14, 16, 17}
	assert.Equal(t, expected, smoothed, "Error smoothing vector")

	x.Sort()
	assert.Equal(t, Vector{2, 2, 2, 2, 4, 5, 50}, x)
}

func TestFixedPush(t *testing.T) {
	arr := make([]float64, 3, 3)

	v := Vector(arr)
	err := v.PushFixed(5.0)
	err = v.PushFixed(25.0)
	err = v.PushFixed(125.0)
	assert.Equal(t, v[2], 125.0)

	err = v.PushFixed(250.0)
	err = v.PushFixed(350.0)
	assert.Equal(t, err, nil)
	assert.Equal(t, v[2], 350.0)
	assert.Equal(t, v[0], 125.0)
	assert.Equal(t, len(v), 3, "Vector length incorrect")
}

func TestPushCapped(t *testing.T) {
	arr := []float64{3.0}

	v := Vector(arr)
	err := v.PushCapped(5.0, 3)
	err = v.PushCapped(25.0, 3)
	err = v.PushCapped(125.0, 3)
	assert.Equal(t, v[2], 125.0, "Last value not at the end of array")
	assert.Equal(t, v[0], 5.0)
	assert.Equal(t, err, nil, fmt.Sprintf("An error occured: %#v", err))
	assert.Equal(t, len(v), 3, "Vector length not equal to three")

	err = v.PushCapped(225.0, 3)
	err = v.PushCapped(325.0, 3)
	assert.Equal(t, v[0], 125.0)
}

func TestPushCappedReduction(t *testing.T) {
	arr := []float64{3.0, 4.0, 5.0, 6.0, 7.0}

	v := Vector(arr)
	err := v.PushCapped(5.0, 3)
	assert.Equal(t, len(v), 3)
	assert.Equal(t, cap(v), 3)
	err = v.PushCapped(25.0, 3)
	err = v.PushCapped(125.0, 3)
	assert.Equal(t, v[2], 125.0, "Last value not at the end of array")
	assert.Equal(t, v[0], 5.0)
	assert.Equal(t, err, nil, fmt.Sprintf("An error occured: %#v", err))
	assert.Equal(t, len(v), 3, "Vector length not equal to three")

	err = v.PushCapped(125.0, 3)
	err = v.PushCapped(125.0, 3)
	assert.Equal(t, v[0], 125.0, "Oldest value invalid")
	assert.Equal(t, len(v), 3, "Array not at expected size")
}
