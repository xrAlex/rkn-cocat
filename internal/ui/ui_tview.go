package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rkn-cocat/internal/entity"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	tviewDialogPageID = "dialog"
	tviewMainPageID   = "main"
	outputScrollStep  = 5
	outputHeaderText  = "[#7dd3fc::b]RKN COCAT[#94a3b8]"
	scrollbarTrackTag = "[#334155]▏"
	scrollbarThumbTag = "[#38bdf8]█"
	defaultFooterText = "[#7dd3fc]Enter[#94a3b8] повторный запуск  [#7dd3fc]Ctrl+C[#94a3b8] выход"
)

var (
	uiColorAppBackground = tcell.GetColor("#020617")
	uiColorPanel         = tcell.GetColor("#0b1220")
	uiColorPanelRaised   = tcell.GetColor("#0f172a")
	uiColorPanelAccent   = tcell.GetColor("#1e293b")
	uiColorBorder        = tcell.GetColor("#334155")
	uiColorBorderActive  = tcell.GetColor("#38bdf8")
	uiColorTitle         = tcell.GetColor("#7dd3fc")
	uiColorTextPrimary   = tcell.GetColor("#e2e8f0")
	uiColorTextMuted     = tcell.GetColor("#94a3b8")
	uiColorTextSubtle    = tcell.GetColor("#64748b")
	uiColorSuccess       = tcell.GetColor("#22c55e")
	uiColorSelectionBG   = tcell.GetColor("#0369a1")
	uiColorSelectionFG   = tcell.GetColor("#f8fafc")

	activitySpinnerFrames = []string{"|", "/", "-", "\\"}

	tviewTestSelectionOptions = []uiTestOption{
		{id: entity.TestSelectionDNSEDE, title: "DNS EDE diagnostics", desc: "Локальные DNS + DoH/DoT, EDE/RCODE/TTL"},
		{id: entity.TestSelectionResolve, title: "DNS-резолв", desc: "Проверка разрешения доменов"},
		{id: entity.TestSelectionTLS13, title: "TLS 1.3", desc: "Проверка доступа к адресу через TLS 1.3"},
		{id: entity.TestSelectionTLS12, title: "TLS 1.2", desc: "Проверка доступа к адресу через TLS 1.2"},
		{id: entity.TestSelectionHTTP, title: "HTTP injection", desc: "Проверка HTTP-инъекций и редиректов"},
		{id: entity.TestSelectionSNIDiff, title: "TLS differential SNI", desc: "Сравнение SNI=target и no-SNI"},
		{id: entity.TestSelectionDNSMatrix, title: "DNS transport matrix", desc: "UDP53 / TCP53 / DoH / DoT"},
		{id: entity.TestSelectionSweep, title: "Size sweep", desc: "Поиск точки обрыва в диапазоне KB"},
		{id: entity.TestSelectionOONI, title: "OONI blocking check", desc: "Сверка блокировок по данным OONI"},
		{id: entity.TestSelectionSaveFile, title: "Save report to file", desc: "Сохранять отчёт в rkn_cocat_results.md"},
	}
)

type uiTestOption struct {
	id    string
	title string
	desc  string
}

type UI struct {
	app       *tview.Application
	pages     *tview.Pages
	output    *tview.TextView
	scrollbar *tview.TextView
	footer    *tview.TextView
	running   atomic.Bool

	activityMu      sync.RWMutex
	activityActive  bool
	activityMessage string
	activityFrame   int
}

type outputScroller struct {
	output    *tview.TextView
	scrollbar *tview.TextView
	update    func()
	dragging  bool
}

func applyTViewTheme() {
	tview.Styles = tview.Theme{
		PrimitiveBackgroundColor:    uiColorAppBackground,
		ContrastBackgroundColor:     uiColorPanelRaised,
		MoreContrastBackgroundColor: uiColorPanelAccent,
		BorderColor:                 uiColorBorder,
		TitleColor:                  uiColorTitle,
		GraphicsColor:               uiColorBorder,
		PrimaryTextColor:            uiColorTextPrimary,
		SecondaryTextColor:          uiColorTextMuted,
		TertiaryTextColor:           uiColorSuccess,
		InverseTextColor:            uiColorSelectionFG,
		ContrastSecondaryTextColor:  uiColorPanel,
	}
}

func New() *UI {
	applyTViewTheme()

	app := tview.NewApplication()
	output := newOutputTextView()
	scrollbar := newScrollbarTextView()
	var pendingOutputRefresh atomic.Bool
	ui := &UI{
		app:       app,
		output:    output,
		scrollbar: scrollbar,
	}

	updateScrollbar := func() {
		renderOutputScrollbar(output, scrollbar)
	}

	scroller := newOutputScroller(output, scrollbar, updateScrollbar)
	scrollbar.SetMouseCapture(scroller.mouseCapture)

	output.SetChangedFunc(func() {
		// tview allows Application.Draw() here, but primitive mutations must stay on the UI thread.
		pendingOutputRefresh.Store(true)
		app.Draw()
	})

	root, footer := newOutputRoot(output, scrollbar)
	pages := tview.NewPages()
	pages.AddPage(tviewMainPageID, root, true, true)
	pages.SetBackgroundColor(uiColorAppBackground)

	app.SetBeforeDrawFunc(func(_ tcell.Screen) bool {
		if pendingOutputRefresh.Swap(false) {
			output.ScrollToEnd()
		}
		ui.refreshFooter()
		updateScrollbar()
		return false
	})

	ui.pages = pages
	ui.footer = footer
	return ui
}

func (ui *UI) OutputWriter() io.Writer {
	if ui == nil {
		return nil
	}
	return ui.output
}

func newOutputTextView() *tview.TextView {
	output := tview.NewTextView().
		SetScrollable(true).
		SetWrap(false).
		SetDynamicColors(true)
	output.SetBorder(true)
	output.SetBorderPadding(0, 0, 1, 1)
	output.SetBorderColor(uiColorBorder)
	output.SetTitleAlign(tview.AlignCenter)
	output.SetTitleColor(uiColorTitle)
	output.SetBackgroundColor(uiColorPanelRaised)
	output.SetTextColor(uiColorTextPrimary)
	output.SetFocusFunc(func() {
		output.SetBorderColor(uiColorBorderActive)
	})
	output.SetBlurFunc(func() {
		output.SetBorderColor(uiColorBorder)
	})
	return output
}

func newScrollbarTextView() *tview.TextView {
	scrollbar := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	scrollbar.SetBorder(false)
	scrollbar.SetBackgroundColor(uiColorPanelRaised)
	scrollbar.SetTextColor(uiColorTextSubtle)
	return scrollbar
}

func newOutputRoot(output *tview.TextView, scrollbar *tview.TextView) (tview.Primitive, *tview.TextView) {
	header := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText(outputHeaderText)
	header.SetBackgroundColor(uiColorPanel)
	header.SetTextColor(uiColorTitle)

	outputPane := tview.NewFlex().
		AddItem(output, 0, 1, true).
		AddItem(scrollbar, 2, 0, false)

	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText(defaultFooterText)
	footer.SetBackgroundColor(uiColorPanel)
	footer.SetTextColor(uiColorTextMuted)

	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(outputPane, 0, 1, true).
		AddItem(footer, 1, 1, false)
	root.SetBackgroundColor(uiColorAppBackground)
	return root, footer
}

func newOutputScroller(output *tview.TextView, scrollbar *tview.TextView, update func()) *outputScroller {
	return &outputScroller{
		output:    output,
		scrollbar: scrollbar,
		update:    update,
	}
}

func (s *outputScroller) scrollByDelta(delta int) {
	if delta == 0 {
		return
	}
	row, col := s.output.GetScrollOffset()
	s.output.ScrollTo(row+delta, col)
	s.update()
}

func (s *outputScroller) setScrollFromMouseY(mouseY int) {
	row := scrollbarYToTopOffset(s.output, s.scrollbar, mouseY)
	_, col := s.output.GetScrollOffset()
	s.output.ScrollTo(row, col)
	s.update()
}

func (s *outputScroller) mouseCapture(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
	if event == nil {
		return action, event
	}

	x, y := event.Position()
	isInside := s.scrollbar.InRect(x, y)

	switch action {
	case tview.MouseScrollUp:
		if isInside {
			s.scrollByDelta(-outputScrollStep)
			return tview.MouseConsumed, nil
		}
	case tview.MouseScrollDown:
		if isInside {
			s.scrollByDelta(outputScrollStep)
			return tview.MouseConsumed, nil
		}
	case tview.MouseLeftDown:
		if isInside {
			s.dragging = true
			s.setScrollFromMouseY(y)
			return tview.MouseConsumed, nil
		}
	case tview.MouseMove:
		if s.dragging {
			s.setScrollFromMouseY(y)
			return tview.MouseConsumed, nil
		}
	case tview.MouseLeftUp:
		if s.dragging {
			s.dragging = false
			if isInside {
				s.setScrollFromMouseY(y)
			}
			return tview.MouseConsumed, nil
		}
	case tview.MouseLeftClick:
		if isInside {
			s.setScrollFromMouseY(y)
			return tview.MouseConsumed, nil
		}
	}

	return action, event
}

func (ui *UI) Run() error {
	if ui == nil || ui.app == nil {
		return nil
	}

	stopAnimation := make(chan struct{})
	ui.running.Store(true)
	defer func() {
		ui.running.Store(false)
		close(stopAnimation)
	}()

	go ui.runActivityAnimation(stopAnimation)
	return ui.app.SetRoot(ui.pages, true).Run()
}

func (ui *UI) Stop() {
	if ui == nil || ui.app == nil {
		return
	}
	ui.app.Stop()
}

func (ui *UI) SetActivity(message string) {
	if ui == nil {
		return
	}

	message = strings.TrimSpace(message)

	ui.activityMu.Lock()
	switch {
	case message == "":
		ui.activityActive = false
		ui.activityMessage = ""
		ui.activityFrame = 0
	default:
		if ui.activityMessage != message {
			ui.activityFrame = 0
		}
		ui.activityActive = true
		ui.activityMessage = message
	}
	ui.activityMu.Unlock()

	if ui.running.Load() && ui.app != nil {
		ui.app.Draw()
	}
}

func (ui *UI) ClearActivity() {
	if ui == nil {
		return
	}
	ui.SetActivity("")
}

func (ui *UI) runActivityAnimation(stop <-chan struct{}) {
	if ui == nil || ui.app == nil {
		return
	}

	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !ui.advanceActivityFrame() {
				continue
			}
			if ui.running.Load() {
				ui.app.Draw()
			}
		}
	}
}

func (ui *UI) advanceActivityFrame() bool {
	if ui == nil {
		return false
	}

	ui.activityMu.Lock()
	defer ui.activityMu.Unlock()

	if !ui.activityActive || len(activitySpinnerFrames) == 0 {
		ui.activityFrame = 0
		return false
	}

	ui.activityFrame = (ui.activityFrame + 1) % len(activitySpinnerFrames)
	return true
}

func (ui *UI) refreshFooter() {
	if ui == nil || ui.footer == nil {
		return
	}

	text := ui.footerText()
	if ui.footer.GetText(false) != text {
		ui.footer.SetText(text)
	}
}

func (ui *UI) footerText() string {
	if ui == nil {
		return defaultFooterText
	}

	ui.activityMu.RLock()
	active := ui.activityActive
	message := ui.activityMessage
	frame := ui.activityFrame
	ui.activityMu.RUnlock()

	if !active || strings.TrimSpace(message) == "" {
		return defaultFooterText
	}

	if len(activitySpinnerFrames) == 0 {
		return fmt.Sprintf("[#22c55e::b]*[#94a3b8] %s", tview.Escape(message))
	}
	return fmt.Sprintf(
		"[#22c55e::b]%s [#7dd3fc]Выполняется[#94a3b8] %s",
		activitySpinnerFrames[frame%len(activitySpinnerFrames)],
		tview.Escape(message),
	)
}

func (ui *UI) showDialog(content tview.Primitive, focus tview.Primitive) {
	ui.pages.RemovePage(tviewDialogPageID)
	ui.pages.AddPage(tviewDialogPageID, content, true, true)
	if focus != nil {
		ui.app.SetFocus(focus)
	}
}

func (ui *UI) hideDialog() {
	ui.pages.RemovePage(tviewDialogPageID)
}

func (ui *UI) WaitForEnter() {
	if ui == nil || ui.app == nil || ui.output == nil {
		return
	}

	doneCh := make(chan struct{}, 1)

	ui.app.QueueUpdateDraw(func() {
		done := false
		previousCapture := ui.output.GetInputCapture()
		ui.app.SetFocus(ui.output)

		ui.output.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event == nil {
				return event
			}
			if event.Key() == tcell.KeyEnter {
				if done {
					return nil
				}
				done = true
				ui.output.SetInputCapture(previousCapture)
				doneCh <- struct{}{}
				return nil
			}
			if previousCapture != nil {
				return previousCapture(event)
			}
			return event
		})
	})

	<-doneCh
}

func (ui *UI) PromptTestSelection(defaultSelection string) (string, error) {
	options := tviewTestSelectionOptions
	resultCh := make(chan string, 1)

	ui.app.QueueUpdateDraw(func() {
		ui.app.EnableMouse(true)
		selected := selectedOptionsFromDefault(options, defaultSelection)

		done := false
		finish := func(useDefaultIfEmpty bool) {
			if done {
				return
			}
			done = true
			ui.hideDialog()
			ui.app.EnableMouse(true)

			selection := selectionFromOptions(options, selected)
			if selection == "" && useDefaultIfEmpty {
				selection = defaultSelection
			}
			resultCh <- selection
		}

		table := newTestSelectionTable(options, selected)
		toggleRow := func(row int) {
			toggleTestSelectionRow(table, options, selected, row)
		}

		table.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
			if event == nil || action != tview.MouseLeftClick {
				return action, event
			}

			x, y := event.Position()
			if !table.InRect(x, y) {
				return action, event
			}

			row, _ := table.CellAt(x, y)
			if !isValidTestSelectionRow(row, options) {
				return action, event
			}

			table.Select(row, 0)
			toggleRow(row)
			return tview.MouseConsumed, nil
		})

		help := tview.NewTextView().
			SetTextAlign(tview.AlignCenter).
			SetDynamicColors(true).
			SetText("[#7dd3fc]Клик/Space[#94a3b8] выбрать/снять  [#7dd3fc]Enter[#94a3b8] запуск")
		help.SetBackgroundColor(uiColorPanel)
		help.SetTextColor(uiColorTextMuted)

		content := tview.NewFlex().
			SetDirection(tview.FlexRow).
			AddItem(table, 0, 1, true).
			AddItem(help, 1, 0, false)
		content.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			switch event.Key() {
			case tcell.KeyEnter:
				finish(true)
				return nil
			}

			switch event.Rune() {
			case ' ':
				row, _ := table.GetSelection()
				toggleRow(row)
				return nil
			}
			return event
		})

		ui.showDialog(centerAdaptivePrimitive(content, 8, 8), table)
	})

	selection := <-resultCh
	return selection, nil
}

func selectedOptionsFromDefault(options []uiTestOption, defaultSelection string) map[string]bool {
	selectedByID := entity.ParseTestSelectionSet(defaultSelection)
	selected := make(map[string]bool, len(options))
	for _, option := range options {
		_, ok := selectedByID[option.id]
		selected[option.id] = ok
	}
	return selected
}

func newTestSelectionTable(options []uiTestOption, selected map[string]bool) *tview.Table {
	table := tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0)
	table.SetBorder(true).
		SetTitle(" Выбор Набора Тестов ").
		SetBorderPadding(0, 0, 1, 1)
	table.SetBorderColor(uiColorBorder)
	table.SetTitleColor(uiColorTitle)
	table.SetBackgroundColor(uiColorPanelRaised)
	table.SetSelectedStyle(tcell.StyleDefault.
		Background(uiColorSelectionBG).
		Foreground(uiColorSelectionFG).
		Bold(true))
	table.SetFocusFunc(func() {
		table.SetBorderColor(uiColorBorderActive)
	})
	table.SetBlurFunc(func() {
		table.SetBorderColor(uiColorBorder)
	})

	headerStyle := tcell.StyleDefault.Foreground(uiColorTitle).Background(uiColorPanelAccent).Bold(true)
	table.SetCell(0, 0, tview.NewTableCell("ON").SetStyle(headerStyle).SetAlign(tview.AlignCenter).SetSelectable(false).SetExpansion(1))
	table.SetCell(0, 1, tview.NewTableCell("ТЕСТ").SetStyle(headerStyle).SetSelectable(false).SetExpansion(2))
	table.SetCell(0, 2, tview.NewTableCell("ОПИСАНИЕ").SetStyle(headerStyle).SetSelectable(false).SetExpansion(5))

	for row := 1; row <= len(options); row++ {
		refreshTestSelectionRow(table, options, selected, row)
	}
	table.Select(1, 0)

	return table
}

func refreshTestSelectionRow(table *tview.Table, options []uiTestOption, selected map[string]bool, row int) {
	if !isValidTestSelectionRow(row, options) {
		return
	}

	option := options[row-1]
	on := "○"
	onColor := uiColorTextSubtle
	if selected[option.id] {
		on = "●"
		onColor = uiColorSuccess
	}

	rowBG := uiColorPanelRaised
	if row%2 == 0 {
		rowBG = uiColorPanel
	}

	statusStyle := tcell.StyleDefault.Foreground(onColor).Background(rowBG)
	if selected[option.id] {
		statusStyle = statusStyle.Bold(true)
	}

	titleStyle := tcell.StyleDefault.Foreground(uiColorTextPrimary).Background(rowBG)
	descStyle := tcell.StyleDefault.Foreground(uiColorTextMuted).Background(rowBG)

	table.SetCell(row, 0, tview.NewTableCell(on).SetAlign(tview.AlignCenter).SetStyle(statusStyle).SetExpansion(1))
	table.SetCell(row, 1, tview.NewTableCell(option.title).SetStyle(titleStyle).SetExpansion(2))
	table.SetCell(row, 2, tview.NewTableCell(option.desc).SetStyle(descStyle).SetExpansion(5))
}

func toggleTestSelectionRow(table *tview.Table, options []uiTestOption, selected map[string]bool, row int) {
	if !isValidTestSelectionRow(row, options) {
		return
	}

	option := options[row-1]
	selected[option.id] = !selected[option.id]
	refreshTestSelectionRow(table, options, selected, row)
}

func isValidTestSelectionRow(row int, options []uiTestOption) bool {
	return row > 0 && row <= len(options)
}

func centerAdaptivePrimitive(primitive tview.Primitive, widthWeight int, heightWeight int) tview.Primitive {
	if widthWeight < 1 {
		widthWeight = 1
	}
	if heightWeight < 1 {
		heightWeight = 1
	}
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(
			tview.NewFlex().
				SetDirection(tview.FlexRow).
				AddItem(nil, 0, 1, false).
				AddItem(primitive, 0, heightWeight, true).
				AddItem(nil, 0, 1, false),
			0, widthWeight, true,
		).
		AddItem(nil, 0, 1, false)
}

func selectionFromOptions(options []uiTestOption, selected map[string]bool) string {
	ids := make([]string, 0, len(options))
	for _, option := range options {
		if selected[option.id] {
			ids = append(ids, option.id)
		}
	}
	return strings.Join(ids, ",")
}

func renderOutputScrollbar(output *tview.TextView, scrollbar *tview.TextView) {
	if output == nil || scrollbar == nil {
		return
	}

	metrics := outputScrollMetrics(output)
	if metrics.Height <= 0 {
		scrollbar.SetText("")
		return
	}

	lines := make([]string, metrics.Height)
	for idx := range lines {
		lines[idx] = scrollbarTrackTag
	}
	for idx := metrics.ThumbTop; idx < metrics.ThumbTop+metrics.ThumbSize && idx < metrics.Height; idx++ {
		lines[idx] = scrollbarThumbTag
	}

	scrollbarText := strings.Join(lines, "\n")
	if scrollbar.GetText(false) != scrollbarText {
		scrollbar.SetText(scrollbarText)
	}
}

type scrollMetrics struct {
	Height    int
	Total     int
	Top       int
	MaxTop    int
	ThumbSize int
	ThumbTop  int
}

func outputScrollMetrics(output *tview.TextView) scrollMetrics {
	if output == nil {
		return scrollMetrics{}
	}

	_, _, _, height := output.GetInnerRect()
	if height <= 0 {
		return scrollMetrics{Height: 0}
	}

	text := output.GetText(false)
	totalLines := strings.Count(text, "\n") + 1
	if totalLines < 1 {
		totalLines = 1
	}

	top, _ := output.GetScrollOffset()
	if top < 0 {
		top = 0
	}

	maxTop := totalLines - height
	if maxTop < 0 {
		maxTop = 0
	}
	if top > maxTop {
		top = maxTop
	}

	thumbSize := 1
	if totalLines > 0 {
		thumbSize = (height * height) / totalLines
	}
	if thumbSize < 1 {
		thumbSize = 1
	}
	if thumbSize > height {
		thumbSize = height
	}

	thumbTop := 0
	if maxTop > 0 && height > thumbSize {
		thumbTop = (top * (height - thumbSize)) / maxTop
	}

	return scrollMetrics{
		Height:    height,
		Total:     totalLines,
		Top:       top,
		MaxTop:    maxTop,
		ThumbSize: thumbSize,
		ThumbTop:  thumbTop,
	}
}

func scrollbarYToTopOffset(output *tview.TextView, scrollbar *tview.TextView, mouseY int) int {
	metrics := outputScrollMetrics(output)
	if metrics.MaxTop <= 0 || metrics.Height <= 0 || scrollbar == nil {
		return 0
	}

	_, barY, _, barHeight := scrollbar.GetRect()
	if barHeight <= 0 {
		barHeight = metrics.Height
	}
	pos := mouseY - barY
	if pos < 0 {
		pos = 0
	}
	if pos >= barHeight {
		pos = barHeight - 1
	}

	usable := barHeight - metrics.ThumbSize
	if usable <= 0 {
		return 0
	}

	if pos > usable {
		pos = usable
	}
	return (pos * metrics.MaxTop) / usable
}
