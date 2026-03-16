package report

type Block interface {
	reportBlock()
}

type Section struct {
	Title  string
	Blocks []Block
}

type Paragraph struct {
	Lines []string
}

func (Paragraph) reportBlock() {}

type Table struct {
	Headers []string
	Rows    [][]string
}

func (Table) reportBlock() {}

type Header struct {
	Title string
	Lines []string
}

func (Header) reportBlock() {}
