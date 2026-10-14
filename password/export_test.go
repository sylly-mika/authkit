package password

func DummyParams(h *Hasher) (Params, error) {
	d, err := decode(h.dummy)
	return d.params, err
}
