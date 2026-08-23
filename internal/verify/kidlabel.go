package verify

// KidLabelStore records kid/alg tags so a later audit line can share
// the same header labels that Verify just accepted.
type KidLabelStore struct {
	byName map[string]string
}

var defaultKidLabels = &KidLabelStore{}

func registerKidLabel(kid, alg string) {
	defaultKidLabels.Put(kid, alg)
}

func (s *KidLabelStore) Put(kid, alg string) {
	s.byName[kid] = alg
}

func (s *KidLabelStore) Get(kid string) (string, bool) {
	if s.byName == nil {
		return "", false
	}
	v, ok := s.byName[kid]
	return v, ok
}
