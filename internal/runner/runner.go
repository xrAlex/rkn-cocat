package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"rkn-cocat/internal/checks/common"
	checksdns "rkn-cocat/internal/checks/dns"
	"rkn-cocat/internal/checks/domain"
	"rkn-cocat/internal/checks/ooni"
	"rkn-cocat/internal/checks/sweep"
	"rkn-cocat/internal/entity"
	"rkn-cocat/internal/report"
)

type Runner struct {
	cfg           entity.GlobalConfig
	out           *report.Writer
	ui            RuntimeUI
	sem           chan struct{}
	reportSink    report.PlainTextSink
	reportBuilder *runReportBuilder
	firstRun      bool
	runIdx        int
}

type RuntimeUI interface {
	OutputWriter() io.Writer
	Run() error
	Stop()
	WaitForEnter()
	PromptTestSelection(defaultSelection string) (string, error)
	SetActivity(message string)
	ClearActivity()
}

type runSelection struct {
	runDNSEDE    bool
	runResolve   bool
	runTLS13     bool
	runTLS12     bool
	runHTTP      bool
	runSNIDiff   bool
	runDNSMatrix bool
	runSweep     bool
	runOONI      bool
	saveToFile   bool
}

type runResults struct {
	sws *entity.SweepStats

	resolveSection   *report.Section
	tls13Section     *report.Section
	tls12Section     *report.Section
	httpSection      *report.Section
	sniSection       *report.Section
	dnsEDESection    *report.Section
	dnsMatrixSection *report.Section
	sweepSection     *report.Section
	ooniSection      *report.Section
}

type statusLegendGroup struct {
	Title string
	Items [][2]string
}

var statusLegendByTest = []statusLegendGroup{
	{
		Title: "Тест 1: DNS EDE diagnostics",
		Items: [][2]string{
			{"VALID / VALID + DNS BLOCK HINT", "Валидный DNS-ответ; второй вариант означает дополнительный hint на блок-направление."},
			{"NXDOMAIN / SERVFAIL / REFUSED / NOERROR EMPTY", "Семантические DNS-исходы без валидных A/AAAA ответов."},
			{"MIXED (...)", "A и AAAA дали разные неблагоприятные исходы."},
			{common.StatusBlocked, "Запрос отклонён на транспорте DNS (например DoH/DoT deny)."},
			{common.StatusTimeout, "Таймаут DNS-запроса."},
			{common.StatusError, "Общая ошибка DNS-запроса/парсинга ответа."},
		},
	},
	{
		Title: "Тест 2: DNS-резолв",
		Items: [][2]string{
			{common.StatusDNSOK, "Домен успешно разрешён DNS."},
			{common.StatusDNSFail, "Имя не разрешилось (NXDOMAIN/ошибка резолвера/фильтрация)."},
			{common.StatusDNSFake, "DNS-ответ указывает на IP из списка заглушек/блок-адресов."},
		},
	},
	{
		Title: "Тест 3-4: TLS 1.3 / TLS 1.2",
		Items: [][2]string{
			{common.StatusOK, "Явных признаков блокировки не найдено."},
			{"BLOCKED / ISP PAGE", "HTTP 451 или редирект/контент, похожий на страницу блокировки."},
			{"TLS DPI / TLS MITM / TLS BLOCK / TLS ERR", "Сетевое вмешательство, подмена сертификата, фильтрация по TLS-профилю или общий TLS-сбой."},
			{"SSL CERT / SSL ERR / SSL INT", "Ошибки проверки сертификата или ошибки TLS/SSL-стека."},
			{"TCP RST / TCP ABORT / REFUSED", "Соединение сброшено/прервано/отклонено."},
			{common.StatusTimeout, "Таймаут TCP/TLS подключения или чтения."},
			{"CONN FAIL / CONN ERR", "Все попытки подключения провалены или ошибка не классифицирована точнее."},
			{"NET UNREACH / HOST UNREACH", "Недоступен маршрут до сети/хоста."},
			{common.StatusGlobalConfigErr, "Некорректные параметры конфигурации/URL."},
		},
	},
	{
		Title: "Тест 5: HTTP injection",
		Items: [][2]string{
			{"OK / REDIR", "Штатный HTTP-ответ или редирект без явных признаков блокировки."},
			{"BLOCKED / ISP PAGE", "HTTP 451 или признаки страницы ограничения доступа."},
			{common.StatusDNSFail, "DNS не разрешил домен."},
			{"TCP RST / REFUSED / TIMEOUT", "TCP-сбой/отклонение/таймаут на HTTP этапе."},
			{"CONN FAIL / CONN ERR", "Сбой подключения без более узкой классификации."},
			{"NET UNREACH / HOST UNREACH", "Недоступен маршрут до сети/хоста."},
			{common.StatusGlobalConfigErr, "Некорректные параметры запроса."},
		},
	},
	{
		Title: "Тест 6: TLS differential SNI",
		Items: [][2]string{
			{common.StatusSNIDPI, "TCP к IP:443 проходит, SNI=target не проходит, без SNI проходит."},
			{common.StatusSNIInconclusive, "SNI=target не проходит, но контроль без SNI тоже не проходит."},
			{common.StatusNoDiff, "С SNI и без SNI поведение одинаковое."},
			{common.StatusTCPFail, "Базовый TCP к IP:443 не проходит, SNI-вердикт ограничен."},
			{"OK + TLS/TCP коды", "В технических колонках TCP/SNI возможны OK и базовые коды из TLS/TCP классификации (TLS DPI, TIMEOUT, RST и т.п.)."},
		},
	},
	{
		Title: "Тест 7: DNS transport matrix",
		Items: [][2]string{
			{common.StatusAllOK, "Все DNS-транспорты (UDP/TCP/DoH/DoT) дали валидный результат."},
			{common.StatusPartial, "Часть транспортов работает, часть нет."},
			{common.StatusBlocked, "По транспорту нет OK/NXDOMAIN исходов."},
			{"OK <ip> / NXDOMAIN / TIMEOUT / ERROR", "Коды в отдельных колонках UDP53/TCP53/DoH/DoT."},
		},
	},
	{
		Title: "Тест 8: Size sweep",
		Items: [][2]string{
			{common.StatusSweepPass, "Поток дочитан до верхней границы sweep-окна."},
			{common.StatusSweepBlock, "Обрыв в диапазоне sweep-окна (признак фильтрации по объёму)."},
			{common.StatusSweepOutside, "Обрыв есть, но вне sweep-диапазона."},
			{common.StatusSweepErr, "Нераспознанный/пустой исход sweep-проверки."},
			{"DNS FAIL / DNS FAKE", "Проблема резолвинга или DNS-подмена цели."},
			{"TIMEOUT / CONN FAIL / CONN ERR / REFUSED / TCP RST / TCP ABORT", "Сетевые коды, которые могут пробрасываться из транспортной диагностики."},
			{common.StatusGlobalConfigErr, "Некорректные параметры sweep/URL."},
		},
	},
	{
		Title: "Тест 9: OONI blocking check",
		Items: [][2]string{
			{common.StatusOK, "В последнем измерении OONI (web_connectivity) явных признаков блокировки нет."},
			{common.StatusBlocked, "OONI пометил blocking строкой (например dns/tcp/ip/http)."},
			{common.StatusOONITCPReachable, "web_connectivity нет, но tcp_connect прошёл на 443/80 (признаки блокировки не подтверждены)."},
			{common.StatusOONITCPFail, "tcp_connect по 443/80 неуспешен; возможна блокировка или инфраструктурный сбой."},
			{"NO_DATA / UNKNOWN", "Недостаточно измерений OONI или формат/ответ не позволил сделать вывод."},
		},
	},
}

func NewRunner(cfg entity.GlobalConfig, out *report.Writer, ui RuntimeUI, reportSink report.PlainTextSink) *Runner {
	return &Runner{
		cfg:           cfg,
		out:           out,
		ui:            ui,
		sem:           make(chan struct{}, cfg.MaxConcurrent),
		reportSink:    reportSink,
		reportBuilder: newRunReportBuilder(cfg),
		firstRun:      true,
		runIdx:        1,
	}
}

func parseRunSelection(selection string) runSelection {
	selected := entity.ParseTestSelectionSet(selection)

	return runSelection{
		runDNSEDE:    hasSelection(selected, entity.TestSelectionDNSEDE),
		runResolve:   hasSelection(selected, entity.TestSelectionResolve),
		runTLS13:     hasSelection(selected, entity.TestSelectionTLS13),
		runTLS12:     hasSelection(selected, entity.TestSelectionTLS12),
		runHTTP:      hasSelection(selected, entity.TestSelectionHTTP),
		runSNIDiff:   hasSelection(selected, entity.TestSelectionSNIDiff),
		runDNSMatrix: hasSelection(selected, entity.TestSelectionDNSMatrix),
		runSweep:     hasSelection(selected, entity.TestSelectionSweep),
		runOONI:      hasSelection(selected, entity.TestSelectionOONI),
		saveToFile:   hasSelection(selected, entity.TestSelectionSaveFile),
	}
}

func hasSelection(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

func (s runSelection) needsDomainPipeline() bool {
	return s.runResolve || s.runTLS13 || s.runTLS12 || s.runHTTP || s.runSNIDiff
}

func (s runSelection) resultPath() string {
	if !s.saveToFile {
		return ""
	}
	return filepath.Join(runnerExeDir(), "rkn_cocat_results.md")
}

func (r *Runner) Run(ctx context.Context) error {
	selectionRaw, err := r.askTestSelection()
	if err != nil {
		return err
	}
	selection := parseRunSelection(selectionRaw)
	resultPath := selection.resultPath()
	stubIPs := buildStubIPSet(r.cfg.DNSBlockIPs)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if r.runIdx == 1 {
			r.printInitialHeader()
		}

		report.WriteSection(r.out, report.Section{Title: fmt.Sprintf("Запуск #%d", r.runIdx)})
		results, execErr := r.executeSelectedTests(ctx, selection, stubIPs)
		if execErr != nil {
			return execErr
		}

		if r.firstRun {
			r.printStatusLegend()
			r.firstRun = false
		}

		report.WriteSection(r.out, r.reportBuilder.buildNarrativeSection(results))

		r.out.Println("")
		r.out.Println("Проверка завершена.")

		if selection.saveToFile && resultPath != "" {
			if r.reportSink == nil {
				r.out.Println("Не удалось сохранить файл: report sink не настроен")
			} else if err := r.reportSink.Save(ctx, resultPath, r.out.String()); err != nil {
				r.out.Println(fmt.Sprintf("Не удалось сохранить файл: %v", err))
			} else {
				r.out.Println(fmt.Sprintf("Результаты сохранены: %s", resultPath))
			}
		}

		r.out.Println("")
		r.out.Println("Нажмите Enter для повторного запуска (Ctrl+C для выхода).")
		if !r.waitForEnter(ctx) {
			return ctx.Err()
		}
		r.runIdx++
	}
}

func (r *Runner) waitForEnter(ctx context.Context) bool {
	waitDone := make(chan struct{}, 1)
	go func() {
		r.ui.WaitForEnter()
		waitDone <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return false
	case <-waitDone:
		return true
	}
}

func (r *Runner) askTestSelection() (string, error) {
	return r.ui.PromptTestSelection(entity.DefaultTestSelection)
}

func (r *Runner) executeSelectedTests(ctx context.Context, selection runSelection, stubIPs map[string]struct{}) (runResults, error) {
	results := runResults{}
	r.clearActivity()
	defer r.clearActivity()

	if selection.runDNSEDE {
		r.printPhaseProgress("DNS EDE diagnostics")
		phase := checksdns.RunEDEDiagnosticsTest(ctx, r.cfg)
		report.WriteSection(r.out, phase.Section)
		section := phase.Section
		results.dnsEDESection = &section
		if err := ctx.Err(); err != nil {
			return results, err
		}
	}

	if selection.needsDomainPipeline() {
		domainPipe := domain.NewPipeline(ctx, r.cfg, r.sem, stubIPs)
		entries := domain.PrepareEntries(ctx, domainPipe, r.cfg.DomainsToCheck)
		if err := ctx.Err(); err != nil {
			return results, err
		}

		if selection.runResolve {
			r.printPhaseProgress("DNS-резолв")
			phase := domainPipe.RunResolveTest(ctx, entries)
			report.WriteSection(r.out, phase.Section)
			section := phase.Section
			results.resolveSection = &section
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}
		if selection.runTLS13 {
			r.printPhaseProgress("TLS 1.3")
			phase := domainPipe.RunTLS13Test(ctx, entries)
			report.WriteSection(r.out, phase.Section)
			section := phase.Section
			results.tls13Section = &section
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}
		if selection.runTLS12 {
			r.printPhaseProgress("TLS 1.2")
			phase := domainPipe.RunTLS12Test(ctx, entries)
			report.WriteSection(r.out, phase.Section)
			section := phase.Section
			results.tls12Section = &section
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}
		if selection.runHTTP {
			r.printPhaseProgress("HTTP injection")
			phase := domainPipe.RunHTTPTest(ctx, entries)
			report.WriteSection(r.out, phase.Section)
			section := phase.Section
			results.httpSection = &section
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}
		if selection.runSNIDiff {
			r.printPhaseProgress("TLS differential SNI")
			phase := domain.RunTLSSNIDifferentialTest(ctx, r.cfg, entries, r.sem)
			report.WriteSection(r.out, phase.Section)
			section := phase.Section
			results.sniSection = &section
			if err := ctx.Err(); err != nil {
				return results, err
			}
		}
	}

	if selection.runDNSMatrix {
		r.printPhaseProgress("DNS transport matrix")
		phase := checksdns.RunTransportMatrixTest(ctx, r.cfg)
		report.WriteSection(r.out, phase.Section)
		section := phase.Section
		results.dnsMatrixSection = &section
		if err := ctx.Err(); err != nil {
			return results, err
		}
	}
	if selection.runSweep {
		r.printPhaseProgress("Size sweep")
		phase := sweep.RunSizeSweepTest(ctx, r.cfg, r.cfg.SweepTargets, r.sem, stubIPs)
		report.WriteSection(r.out, phase.Section)
		results.sws = &phase.Stats
		section := phase.Section
		results.sweepSection = &section
		if err := ctx.Err(); err != nil {
			return results, err
		}
	}
	if selection.runOONI {
		r.printPhaseProgress("OONI blocking check")
		phase := ooni.RunBlockingTest(ctx, r.cfg, func(done int, total int, target string) {
			r.setActivity(fmt.Sprintf("OONI %d/%d: %s", done, total, target))
		})
		report.WriteSection(r.out, phase.Section)
		section := phase.Section
		results.ooniSection = &section
		if err := ctx.Err(); err != nil {
			return results, err
		}
	}

	return results, nil
}

func (r *Runner) printPhaseProgress(name string) {
	if r == nil {
		return
	}
	r.setActivity(name)
}

func (r *Runner) setActivity(message string) {
	if r == nil || r.ui == nil {
		return
	}
	r.ui.SetActivity(message)
}

func (r *Runner) clearActivity() {
	if r == nil || r.ui == nil {
		return
	}
	r.ui.ClearActivity()
}

func (r *Runner) printInitialHeader() {
	report.WriteHeader(r.out, buildInitialHeader(r.cfg))
	report.WriteSection(r.out, buildInitialConfigSection(r.cfg))
}

func (r *Runner) printStatusLegend() {
	blocks := make([]report.Block, 0, len(statusLegendByTest)*2)
	for idx, group := range statusLegendByTest {
		if idx > 0 {
			blocks = append(blocks, report.Paragraph{Lines: []string{""}})
		}
		legendRows := make([][]string, 0, len(group.Items))
		for _, item := range group.Items {
			legendRows = append(legendRows, []string{item[0], item[1]})
		}
		blocks = append(blocks, report.Paragraph{Lines: []string{group.Title}})
		blocks = append(blocks, report.Table{
			Headers: []string{"Код", "Описание"},
			Rows:    legendRows,
		})
	}
	report.WriteSection(r.out, report.Section{
		Title:  "Легенда Статусов",
		Blocks: blocks,
	})
}

func runnerExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		cwd, _ := os.Getwd()
		return cwd
	}
	return filepath.Dir(exe)
}

func buildStubIPSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	return out
}
