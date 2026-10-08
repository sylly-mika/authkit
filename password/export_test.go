package password

// DummyParams is the parameters h's dummy hash was made under.
func DummyParams(h *Hasher) (Params, error) {
	d, err := decode(h.dummy)
	return d.params, err
}
