package osservices

type OSDatapath interface {
	InitDatapath(filter string) error
	StartDataPath() error
}

type OSTrafficFilter interface {
	ConfigureFilter(filters []string) error
	ListFilters() []string
	AddFilter(criteria []string)
	DeleteFilter(criteria []string)
}
