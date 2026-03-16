package entity

type SNIDiffStats struct {
	Total                 int
	Confirmed             int
	NoDiff                int
	Inconclusive          int
	Error                 int
	ConfirmedResources    []string
	InconclusiveResources []string
	ErrorResources        []string
}
