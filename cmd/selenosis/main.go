package main

import (
	selenosisfiber "github.com/Roman-Mitusov/selenosis-fiber"
	"github.com/Roman-Mitusov/selenosis-fiber/browser"
	"github.com/Roman-Mitusov/selenosis-fiber/config"
	"github.com/fsnotify/fsnotify"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var buildVersion = "HEAD"

//Command ...
func command() *cobra.Command {

	var (
		cfgFile             string
		address             string
		proxyPort           string
		namespace           string
		service             string
		imagePullSecretName string
		proxyImage          string
		sessionRetryCount   int
		limit               int
		browserWaitTimeout  time.Duration
		sessionWaitTimeout  time.Duration
		sessionIdleTimeout  time.Duration
		shutdownTimeout     time.Duration
	)

	cmd := &cobra.Command{
		Use:   "selenosis",
		Short: "Scallable, stateless selenium grid for Kubernetes cluster",
		Run: func(cmd *cobra.Command, args []string) {

			logger := logrus.New()
			logger.Infof("Starting selenosis %s", buildVersion)

			browsers, err := config.NewBrowsersConfig(cfgFile)
			if err != nil {
				logger.Fatalf("Failed to read config: %v", err)
			}

			logger.Info("Browsers config file loaded")

			go runConfigWatcher(logger, cfgFile, browsers)

			logger.Info("config watcher started")

			client, err := browser.NewClient(browser.ClientConfig{
				Namespace:           namespace,
				Service:             service,
				ReadinessTimeout:    browserWaitTimeout,
				IdleTimeout:         sessionIdleTimeout,
				ServicePort:         proxyPort,
				ImagePullSecretName: imagePullSecretName,
				ProxyImage:          proxyImage,
			})

			if err != nil {
				logger.Fatalf("failed to create kubernetes client: %v", err)
			}

			logger.Info("kubernetes client created")

			hostname, _ := os.Hostname()

			app := selenosisfiber.New(logger, client, browsers, selenosisfiber.Configuration{
				SelenosisHost:      hostname,
				ServiceName:        service,
				SidecarPort:        proxyPort,
				SessionLimit:       limit,
				SessionRetryCount:  sessionRetryCount,
				BrowserWaitTimeout: browserWaitTimeout,
				SessionIdleTimeout: sessionIdleTimeout,
				BuildVersion:       buildVersion,
			})

			router := fiber.New(fiber.Config{
				DisableStartupMessage: true,
				StrictRouting:         true,
			})

			router.Use(recover.New())//requestid.New(),
			//	fiberlog.New(fiberlog.Config{
			//	Format: "[${time}] | request_id: ${locals:requestid} | status_code: ${status} | http_method: ${method} | client_ip: ${ip} | path: ${path} | request_body: ${body} | response: ${resBody}\n",
			//}	)

			router.Post("/wd/hub/session", app.CheckLimit(app.HandleSession))
			router.All("/wd/hub/session/:sessionId/*", app.HandleProxy)
			router.Get("/wd/hub/status", app.HandleHubStatus)
			router.Get("/vnc/:sessionId", app.ProxyVNC())
			router.Get("/logs/:sessionId", app.ProxyLogs())
			router.Get("/devtools/{sessionId}", app.HandleReverseProxy)
			router.Get("/download/{sessionId}", app.HandleReverseProxy)
			router.Get("/clipboard/{sessionId}", app.HandleReverseProxy)
			router.Get("/status", app.HandleStatus)
			router.Get("/healthz", func(ctx *fiber.Ctx) error {
				return ctx.SendStatus(fiber.StatusOK)
			})

			stop := make(chan os.Signal)
			signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGKILL, os.Interrupt)

			e := make(chan error)

			go func() {
				_ = <-stop
				logger.Info("Gracefully shutting down selenosis ...")
				_ = router.Shutdown()
			}()

			go func() {
				e <- router.Listen(address)
			}()

			select {
			case err := <-e:
				logger.Fatalf("Failed to start selenosis: %v", err)
			case <-stop:
				logger.Info("Stopping selenosis ...")
			}

		},
	}

	cmd.Flags().StringVar(&address, "port", ":4444", "port for selenosis")
	cmd.Flags().StringVar(&proxyPort, "proxy-port", "4445", "proxy continer port")
	cmd.Flags().StringVar(&cfgFile, "browsers-config", "./config/browsers.yaml", "browsers config")
	cmd.Flags().IntVar(&limit, "browser-limit", 10, "active sessions max limit")
	cmd.Flags().StringVar(&namespace, "namespace", "selenosis", "kubernetes namespace")
	cmd.Flags().StringVar(&service, "service-name", "seleniferous", "kubernetes service name for browsers")
	cmd.Flags().DurationVar(&browserWaitTimeout, "browser-wait-timeout", 30*time.Second, "time in seconds that a browser will be ready")
	cmd.Flags().DurationVar(&sessionWaitTimeout, "session-wait-timeout", 60*time.Second, "time in seconds that a session will be ready")
	cmd.Flags().DurationVar(&sessionIdleTimeout, "session-idle-timeout", 5*time.Minute, "time in seconds that a session will idle")
	cmd.Flags().IntVar(&sessionRetryCount, "session-retry-count", 3, "session retry count")
	cmd.Flags().DurationVar(&shutdownTimeout, "graceful-shutdown-timeout", 30*time.Second, "time in seconds  gracefull shutdown timeout")
	cmd.Flags().StringVar(&imagePullSecretName, "image-pull-secret-name", "", "secret name to private registry")
	cmd.Flags().StringVar(&proxyImage, "proxy-image", "alcounit/seleniferous:latest", "in case you use private registry replace with image from private registry")
	cmd.Flags().SortFlags = false

	return cmd
}

func runConfigWatcher(logger *logrus.Logger, filename string, config *config.BrowsersConfig) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logger.Fatalf("failed to create watcher: %v", err)
		}
		defer watcher.Close()

		configFile := filepath.Clean(filename)
		configDir, _ := filepath.Split(configFile)
		realConfigFile, _ := filepath.EvalSymlinks(filename)

		done := make(chan bool)
		go func() {
			for {
				select {
				case event := <-watcher.Events:
					currentConfigFile, _ := filepath.EvalSymlinks(filename)
					if (filepath.Clean(event.Name) == configFile &&
						(event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create)) ||
						(currentConfigFile != "" && currentConfigFile != realConfigFile) {

						realConfigFile = currentConfigFile
						err := config.Reload()
						if err != nil {
							logger.Errorf("config reload failed: %v", err)
						} else {
							logger.Infof("config %s reloaded", configFile)
						}
					}
				case err := <-watcher.Errors:
					logger.Errorf("config watcher error: %v", err)
				}
			}
		}()
		_ = watcher.Add(configDir)
		wg.Done()
		<-done
	}()
	wg.Wait()
}

func main() {
	if err := command().Execute(); err != nil {
		os.Exit(1)
	}
}
