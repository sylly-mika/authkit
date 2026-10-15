package authkit

// Core is a module's handle on the Service: sessions, the login throttle, Admit and the sign-in log. Its API is unstable until v1.0.0.
type Core struct {
	s    *Service
	name string
}
